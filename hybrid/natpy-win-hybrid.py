#!/usr/bin/env python3

import re
import select
import socket
import struct
import subprocess
import threading
import hmac
import argparse
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple


_TCP_BUF        = 65536
_UDP_BUF        = 65536
_TCP_IDLE       = 60.0
_UDP_IDLE       = 120.0
_DNS_TTL        = 300
_DNS_NEG_TTL    = 30
_BACKLOG        = 128
_HTTP_HDR_LIMIT = 8192


class _DnsCache:
    def __init__(self):
        self._store: dict[str, Tuple[Optional[str], float]] = {}
        self._lock = threading.Lock()

    def resolve(self, host: str) -> Optional[str]:
        now = time.monotonic()
        with self._lock:
            entry = self._store.get(host)
            if entry is not None:
                ip, exp = entry
                if now < exp:
                    return ip
                del self._store[host]

        try:
            ip = socket.gethostbyname(host)
        except OSError:
            ip = None

        ttl = _DNS_TTL if ip else _DNS_NEG_TTL
        with self._lock:
            self._store[host] = (ip, time.monotonic() + ttl)
        return ip


class _RelayMixin:
    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(_TCP_BUF)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _relay_tcp(self, client: socket.socket, remote: socket.socket) -> None:
        client.settimeout(_TCP_IDLE)
        remote.settimeout(_TCP_IDLE)

        t = threading.Thread(target=self._pump, args=(client, remote), daemon=True)
        t.start()
        self._pump(remote, client)
        t.join()

        for s in (client, remote):
            try:
                s.close()
            except OSError:
                pass

    def _verify_credentials(self, user: bytes, pwd: bytes) -> bool:
        if not self.require_auth:
            return True
        return (
            hmac.compare_digest(user, self._user_b)
            and hmac.compare_digest(pwd, self._pwd_b)
        )

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)


class HttpProxy(_RelayMixin):
    def __init__(
        self,
        host: str,
        port: int,
        username: Optional[str],
        password: Optional[str],
        max_workers: int,
        dns: _DnsCache,
    ):
        self.host         = host
        self.port         = port
        self.require_auth = bool(username and password)
        self.running      = True
        self._max_workers = max_workers
        self._dns         = dns

        self._user_b = username.encode() if username else b""
        self._pwd_b  = password.encode() if password else b""

        self._total  = 0
        self._active = 0

    def _check_proxy_auth(self, headers: dict) -> bool:
        if not self.require_auth:
            return True
        auth = headers.get("proxy-authorization", "")
        if not auth.lower().startswith("basic "):
            return False
        import base64
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", errors="replace")
            user, _, pwd = decoded.partition(":")
        except Exception:
            return False
        return self._verify_credentials(user.encode(), pwd.encode())

    @staticmethod
    def _parse_http_request(raw: bytes) -> Optional[Tuple[str, str, dict, bytes]]:
        sep = raw.find(b"\r\n\r\n")
        if sep == -1:
            return None
        header_block = raw[:sep]
        lines = header_block.split(b"\r\n")
        if not lines:
            return None

        try:
            request_line = lines[0].decode("latin-1")
            method, target, _version = request_line.split(" ", 2)
        except ValueError:
            return None

        headers = {}
        for line in lines[1:]:
            if b":" not in line:
                continue
            k, _, v = line.partition(b":")
            headers[k.decode("latin-1").strip().lower()] = v.decode("latin-1").strip()

        return method, target, headers, header_block

    def handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        self._total  += 1
        self._active += 1
        remote = None
        try:
            client_sock.settimeout(15)

            raw = bytearray()
            while b"\r\n\r\n" not in raw and len(raw) < _HTTP_HDR_LIMIT:
                chunk = self._recv_exact(client_sock, 1)
                if chunk is None:
                    return
                raw += chunk

            parsed = self._parse_http_request(bytes(raw))
            if parsed is None:
                return
            method, target, headers, _ = parsed

            if not self._check_proxy_auth(headers):
                client_sock.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b'Proxy-Authenticate: Basic realm="proxy"\r\n'
                    b"Content-Length: 0\r\n\r\n"
                )
                return

            if method.upper() == "CONNECT":
                host, _, port_s = target.partition(":")
                port = int(port_s) if port_s else 443
            else:
                host_hdr = headers.get("host", "")
                host, _, port_s = host_hdr.partition(":")
                port = int(port_s) if port_s else 80
                if not host:
                    return

            dest_ip = self._dns.resolve(host) if not re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else host
            if dest_ip is None:
                client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                return

            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(15)
            remote.connect((dest_ip, port))

            for s in (client_sock, remote):
                try:
                    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass

            if method.upper() == "CONNECT":
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                remote.sendall(bytes(raw))

            self._relay_tcp(client_sock, remote)
            client_sock = None
            remote = None

        except Exception:
            pass
        finally:
            for s in (client_sock, remote):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass
            self._active -= 1

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(_BACKLOG)
        print(f"[*] HTTP Proxy     : {self.host}:{self.port}  (TCP only)")

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            while self.running:
                try:
                    client_sock, client_addr = server.accept()
                    pool.submit(self.handle_client, client_sock, client_addr)
                except KeyboardInterrupt:
                    break
                except OSError:
                    pass

        server.close()


class Socks5Proxy(_RelayMixin):
    def __init__(
        self,
        host: str,
        port: int,
        username: Optional[str],
        password: Optional[str],
        max_workers: int,
        dns: _DnsCache,
    ):
        self.host         = host
        self.port         = port
        self.require_auth = bool(username and password)
        self.running      = True
        self._max_workers = max_workers
        self._dns         = dns

        self._user_b = username.encode() if username else b""
        self._pwd_b  = password.encode() if password else b""

        self._total      = 0
        self._active     = 0
        self._auth_ok    = 0
        self._auth_fail  = 0
        self._udp_sess   = 0

    def _do_handshake(self, sock: socket.socket) -> bool:
        hdr = self._recv_exact(sock, 2)
        if not hdr or hdr[0] != 0x05:
            return False

        methods = self._recv_exact(sock, hdr[1])
        if methods is None:
            return False

        if self.require_auth:
            if 0x02 not in methods:
                sock.sendall(b"\x05\xFF")
                return False
            sock.sendall(b"\x05\x02")

            if not self._recv_exact(sock, 1):
                return False
            ulen = self._recv_exact(sock, 1)
            if not ulen:
                return False
            user = self._recv_exact(sock, ulen[0]) or b""
            plen = self._recv_exact(sock, 1)
            if not plen:
                return False
            pwd = self._recv_exact(sock, plen[0]) or b""

            if self._verify_credentials(user, pwd):
                sock.sendall(b"\x01\x00")
                self._auth_ok += 1
                return True
            sock.sendall(b"\x01\x01")
            self._auth_fail += 1
            return False

        sock.sendall(b"\x05\x00")
        return True

    def _parse_request(self, sock: socket.socket) -> Optional[Tuple[int, str, int]]:
        hdr = self._recv_exact(sock, 4)
        if not hdr or hdr[0] != 0x05:
            return None

        cmd  = hdr[1]
        atyp = hdr[3]

        if cmd not in (0x01, 0x03):
            sock.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return None

        if atyp == 0x01:
            raw = self._recv_exact(sock, 6)
            if not raw:
                return None
            dest_ip   = socket.inet_ntoa(raw[:4])
            dest_port = struct.unpack_from(">H", raw, 4)[0]

        elif atyp == 0x03:
            dlen_b = self._recv_exact(sock, 1)
            if not dlen_b:
                return None
            raw = self._recv_exact(sock, dlen_b[0] + 2)
            if not raw:
                return None
            domain    = raw[: dlen_b[0]].decode("utf-8", errors="replace")
            dest_port = struct.unpack_from(">H", raw, dlen_b[0])[0]
            dest_ip   = self._dns.resolve(domain)
            if dest_ip is None:
                sock.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)
                return None

        elif atyp == 0x04:
            sock.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return None

        else:
            return None

        return cmd, dest_ip, dest_port

    def _relay_udp(
        self,
        ctrl_sock: socket.socket,
        client_addr: Tuple[str, int],
    ) -> None:
        self._udp_sess += 1
        relay_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            relay_sock.bind(("0.0.0.0", 0))
            relay_sock.setblocking(False)
            ctrl_sock.setblocking(False)

            _, local_port = relay_sock.getsockname()
            bound_ip = socket.inet_aton(
                self.host if self.host != "0.0.0.0" else "127.0.0.1"
            )
            reply = b"\x05\x00\x00\x01" + bound_ip + struct.pack(">H", local_port)
            try:
                ctrl_sock.sendall(reply)
            except OSError:
                return

            last_src: Optional[Tuple[str, int]] = None
            deadline = time.monotonic() + _UDP_IDLE

            while time.monotonic() < deadline:
                try:
                    r, _, _ = select.select([relay_sock, ctrl_sock], [], [], 5.0)
                except OSError:
                    break

                if not r:
                    continue

                if ctrl_sock in r:
                    try:
                        if not ctrl_sock.recv(1):
                            break
                    except OSError:
                        break

                if relay_sock in r:
                    try:
                        data, addr = relay_sock.recvfrom(_UDP_BUF)
                    except OSError:
                        continue

                    deadline = time.monotonic() + _UDP_IDLE

                    if last_src is None or addr == last_src:
                        parsed = self._parse_udp_header(data)
                        if parsed:
                            payload, dest = parsed
                            last_src = addr
                            try:
                                relay_sock.sendto(payload, dest)
                            except OSError:
                                pass
                    else:
                        if last_src:
                            wrapped = self._build_udp_header(addr) + data
                            try:
                                relay_sock.sendto(wrapped, last_src)
                            except OSError:
                                pass

        finally:
            relay_sock.close()
            self._udp_sess -= 1

    @staticmethod
    def _parse_udp_header(data: bytes) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        if len(data) < 10:
            return None

        if data[2] != 0:
            return None

        atyp = data[3]

        if atyp == 0x01:
            dest_ip   = socket.inet_ntoa(data[4:8])
            dest_port = struct.unpack_from(">H", data, 8)[0]
            payload   = data[10:]
        elif atyp == 0x03:
            dlen = data[4]
            if len(data) < 5 + dlen + 2:
                return None
            dest_ip = socket.gethostbyname(
                data[5 : 5 + dlen].decode("utf-8", errors="replace")
            )
            dest_port = struct.unpack_from(">H", data, 5 + dlen)[0]
            payload   = data[5 + dlen + 2 :]
        else:
            return None

        return payload, (dest_ip, dest_port)

    @staticmethod
    def _build_udp_header(src_addr: Tuple[str, int]) -> bytes:
        return (
            b"\x00\x00"
            + b"\x00"
            + b"\x01"
            + socket.inet_aton(src_addr[0])
            + struct.pack(">H", src_addr[1])
        )

    def handle_client(self, client_sock: socket.socket, addr: tuple) -> None:
        self._total  += 1
        self._active += 1
        try:
            client_sock.settimeout(15)

            if not self._do_handshake(client_sock):
                return

            result = self._parse_request(client_sock)
            if result is None:
                return

            cmd, dest_ip, dest_port = result

            if cmd == 0x03:
                self._relay_udp(client_sock, (dest_ip, dest_port))
                return

            try:
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(15)
                remote.connect((dest_ip, dest_port))

                for s in (client_sock, remote):
                    try:
                        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except OSError:
                        pass

                reply = (
                    b"\x05\x00\x00\x01"
                    + socket.inet_aton(dest_ip)
                    + struct.pack(">H", dest_port)
                )
                client_sock.sendall(reply)

                self._relay_tcp(client_sock, remote)
                client_sock = None

            except OSError:
                try:
                    client_sock.sendall(b"\x05\x01\x00\x01" + b"\x00" * 6)
                except OSError:
                    pass

        except Exception:
            pass
        finally:
            if client_sock is not None:
                try:
                    client_sock.close()
                except OSError:
                    pass
            self._active -= 1

    def start(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.host, self.port))
        server.listen(_BACKLOG)
        print(f"[*] SOCKS5 Proxy   : {self.host}:{self.port}  (TCP + UDP, NAT fix)")

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            while self.running:
                try:
                    client_sock, client_addr = server.accept()
                    pool.submit(self.handle_client, client_sock, client_addr)
                except KeyboardInterrupt:
                    break
                except OSError:
                    pass

        server.close()


def detect_listen_address() -> str:
    _IP_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, shell=True, timeout=5
        )
        adapter = None
        for line in result.stdout.splitlines():
            s = line.strip()
            if "Ethernet adapter" in s or "Wireless LAN adapter" in s:
                adapter = s
            elif "IPv4 Address" in s and adapter:
                if "Realtek" in adapter or "USB" in adapter:
                    m = _IP_RE.search(s)
                    if m:
                        ip = m.group(1)
                        if ip.startswith(("192.168.", "10.")):
                            return ip
    except Exception:
        pass
    return "0.0.0.0"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VPN Hybrid Proxy (HTTP + SOCKS5) for Windows, with UDP support for Xbox NAT"
    )
    parser.add_argument("--host",       help="Listen address (auto-detected if omitted)")
    parser.add_argument("--http-port",  type=int, default=9897, help="HTTP proxy port (default 9897)")
    parser.add_argument("--socks-port", type=int, default=9898, help="SOCKS5 proxy port (default 9898)")
    parser.add_argument("--user",       help="Username for authentication (applies to both proxies)")
    parser.add_argument("--password",   help="Password for authentication (applies to both proxies)")
    parser.add_argument("--workers",    type=int, default=256, help="Thread pool size per server (default 256)")
    args = parser.parse_args()

    host = args.host or detect_listen_address()
    dns  = _DnsCache()

    http_proxy  = HttpProxy(host, args.http_port, args.user, args.password, args.workers, dns)
    socks_proxy = Socks5Proxy(host, args.socks_port, args.user, args.password, args.workers, dns)

    print(f"[*] Listen address : {host}")
    print(f"[*] Authentication : {'Enabled' if (args.user and args.password) else 'Disabled'}")

    http_thread = threading.Thread(target=http_proxy.start, daemon=True)
    http_thread.start()

    try:
        socks_proxy.start()
    finally:
        http_proxy.running  = False
        socks_proxy.running = False


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Shutdown requested")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
