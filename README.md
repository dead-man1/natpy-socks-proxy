# NaTPY - SOCKS5 Proxy with UDP Support for Gaming

**A lightweight SOCKS5 proxy server designed to share VPN connections while properly handling UDP — Perfect for fixing NAT Type issues on gaming consoles like Xbox and PlayStation.**

---

### ✨ Key Features

- **Full UDP ASSOCIATE support** — Essential for Xbox NAT Type detection (STUN works correctly)
- **Share VPN connection** over your local network (LAN)
- **Optional Username/Password authentication**
- **Smart DNS Cache** with separate TTL for success and failure
- **Efficient TCP relay** using `select()` + `TCP_NODELAY` for low latency
- **Optimized UDP relay** with long idle timeout (keeps STUN sessions alive)
- **Automatic network adapter detection** (prioritizes Realtek/USB VPN adapters)
- **Configurable Thread Pool** (default 256 workers)
- **Lightweight & low resource usage**

---
> [!Note]
> ### Hybrid Version includes both `Socks5` and `HTTP` Server for Direct use on Playstation but NAT detection and UDP relay will not work on the HTTP
### 🎮 Why NaTPY?

Most SOCKS5 proxies only support TCP, causing gaming consoles to show **NAT Type: Unavailable** or **Strict**.  
**NaTPY** implements proper UDP relaying according to the SOCKS5 protocol, allowing STUN requests to succeed and helping you achieve **NAT Type: Open**.

---

## 🚀 Using With Authentication

### Method 1 : Using Command Prompt (CMD) 
Open Command Prompt (CMD) as Administrator (recommended).
Navigate to the folder where NaTPY.py is located using the
```
cd C:\Path\To\Your\NaTPY\Folder
```
and run the NatPY with this command 
```
python natpy-win.py --host 0.0.0.0 --user yourusername --password yourpassword
```

--host 0.0.0.0 → Listen on all interfaces (Not Secure)

Replace username and password with your desired credentials.

### 2. Easy Launch with Batch File

For easier daily use, create a file named Start-NaTPY.bat and paste the following content:
```
@echo off
mode con cols=50 lines=15
color 0A
title NaTPY - SOCKS5 Proxy for Gaming

echo.
echo ========================
echo    NaTPY SOCKS5 Proxy
echo ========================
echo.

python natpy-win.py --host 0.0.0.0 --user username --password password

echo.
echo Proxy has stopped or was closed.
pause
```
Paste the code above into a new text file.
Change username and password to your own.
Save the file as Start-NaTPY.bat (make sure the extension is .bat).
Double-click the Start-NaTPY.bat file to run the proxy easily.

## 📱 Installation & Running on Android (Termux)
You can also run NaTPY on Android using Termux.
Steps :

1. Download and Install Termux from F-Droid (recommended) or GitHub.

2. Open Termux and run the following commands :

```
pkg update && pkg upgrade -y
pkg install python iproute2 -y
```

3. Prepare the file on your android device :
   
Create a new folder in your device's internal storage and name it server (or any name you prefer).
Copy the file natpy-android.py into this folder.

navigate to your folder :
```
cd /storage/emulated/0/server
```

Now you can run the server with this command :

```
python natpy-android.py --host 0.0.0.0 --port 9898 --user username --password password
```

> [!WARNING]
> **Using `0.0.0.0`** makes the proxy listen on **all network interfaces**.  
> **While this is convenient for easy connection from other devices, it also means anyone on your local network can potentially access the proxy.**

> [!TIP]
> ### ✅ Secure Way
> 
> Instead of `0.0.0.0`, use your device's **local IP address** (e.g. `192.168.1.105`).
> 
> **How to find your local IP :**
> - **On Windows:** Run `ipconfig` in CMD and look for **IPv4 Address** under your active adapter.
> - **On Termux/Android:** Run `ifconfig` or `ip addr show` and look for the IP under `wlan0`.
