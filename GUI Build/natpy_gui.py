import sys
import os
import json
import time
import threading
from collections import deque
from pathlib import Path

from PySide6.QtCore import Qt, QTimer, QRectF
from PySide6.QtGui import QPainter, QPen, QColor, QPainterPath, QFont
from PySide6.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QCheckBox,
    QFrame,
    QMessageBox,
)

from natpy import VPNSocks5Proxy

BG          = "#0F1420"
SURFACE     = "#171D2B"
FIELD_FILL  = "#1D2434"
ACCENT      = "#00664c"
Initiate      = "#00b386"
IDLE        = "#5B6478"
DANGER      = "#E5484D"
Disconnect       = "#ff8000"
TEXT_PRIMARY   = "#EDEFF4"
TEXT_SECONDARY = "#8891A6"
DOWN_COLOR     = "#22C55E"
UP_COLOR       = "#A855F7"

STYLESHEET = f"""
QWidget {{
    background-color: {BG};
    color: {TEXT_PRIMARY};
    font-family: Segoe UI;
    font-size: 14px;
}}
QLineEdit {{
    background-color: {FIELD_FILL};
    border: none;
    border-radius: 10px;
    padding: 10px 12px;
    color: {TEXT_PRIMARY};
}}
QLineEdit:focus {{
    border: 1px solid {ACCENT};
}}
QLabel[role="caption"] {{
    color: {TEXT_SECONDARY};
    font-size: 12px;
}}
QLabel[role="fieldLabel"] {{
    color: {TEXT_SECONDARY};
    font-size: 12px;
    margin-bottom: 2px;
}}
QCheckBox {{
    color: {TEXT_SECONDARY};
    font-size: 12px;
}}
"""


def config_dir() -> Path:
    appdata = os.environ.get("APPDATA")
    if appdata:
        d = Path(appdata) / "NatpyProxy"
    else:
        d = Path.home() / ".natpy_proxy"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


class ConfigStore:
    def __init__(self):
        self.path = config_dir() / "natpy.conf"

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save(self, host: str, port: str, username: str, password: str) -> None:
        data = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        }
        try:
            self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass


class ConnectionBadge(QFrame):
    def __init__(self):
        super().__init__()
        self.setFixedSize(168, 168)
        self._count_label = QLabel("0")
        self._caption_label = QLabel("Active Users")

        self._count_label.setAlignment(Qt.AlignCenter)
        self._caption_label.setAlignment(Qt.AlignCenter)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._count_label)
        layout.addWidget(self._caption_label)

        self._spin_active = False
        self._spin_angle = 0
        self._spin_direction = 1
        self._target_running = False

        self._spin_timer = QTimer(self)
        self._spin_timer.timeout.connect(self._advance_spin)

        self._finish_timer = QTimer(self)
        self._finish_timer.setSingleShot(True)
        self._finish_timer.timeout.connect(self._finish_spin)

        self.set_running(False, animate=False)

    def set_count(self, value: int) -> None:
        self._count_label.setText(str(value))

    def set_running(self, running: bool, animate: bool = True) -> None:
        if not animate:
            self._spin_timer.stop()
            self._finish_timer.stop()
            self._spin_active = False
            self.update()
            self._apply_flat_style(running)
            return
        self._start_spin(direction=1 if running else -1, target_running=running)

    def _start_spin(self, direction: int, target_running: bool) -> None:
        self._spin_angle = 0
        self._spin_direction = direction
        self._spin_active = True
        self._target_running = target_running
        self._apply_flat_style(not target_running)
        self._spin_timer.start(16)
        self._finish_timer.start(900)

    def _advance_spin(self) -> None:
        self._spin_angle = (self._spin_angle + 12 * self._spin_direction) % 360
        self.update()

    def _finish_spin(self) -> None:
        self._spin_timer.stop()
        self._spin_active = False
        self.update()
        self._apply_flat_style(self._target_running)

    def _apply_flat_style(self, running: bool) -> None:
        bg = ACCENT if running else SURFACE
        text_color = "#eeeeee" if running else TEXT_PRIMARY
        caption_color = "#eeeeee" if running else TEXT_SECONDARY
        self.setStyleSheet(
            f"QFrame {{ border-radius: 84px; border: none; background-color: {bg}; }}"
        )
        self._count_label.setStyleSheet(
            f"font-size: 46px; font-weight: 800; color: {text_color}; border: none;"
        )
        self._caption_label.setStyleSheet(
            f"font-size: 12px; color: {caption_color}; border: none;"
        )

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if not self._spin_active:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen_width = 4
        margin = pen_width / 2 + 1
        rect = QRectF(margin, margin, self.width() - 2 * margin, self.height() - 2 * margin)
        pen = QPen(QColor(Initiate if self._spin_direction > 0 else Disconnect))
        pen.setWidth(pen_width)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        span_angle = 100 * 16
        start_angle = int(-self._spin_angle * 16)
        painter.drawArc(rect, start_angle, span_angle)
        painter.end()


def _format_rate(bytes_per_sec: float) -> str:
    if bytes_per_sec >= 1024 * 1024:
        return f"{bytes_per_sec / (1024 * 1024):.1f} MB/s"
    if bytes_per_sec >= 1024:
        return f"{bytes_per_sec / 1024:.0f} KB/s"
    return f"{bytes_per_sec:.0f} B/s"


class BandwidthGraph(QFrame):
    HISTORY   = 40
    SAMPLE_MS = 500

    def __init__(self):
        super().__init__()
        self.setFixedHeight(110)
        self.setStyleSheet(
            f"QFrame {{ background-color: {SURFACE}; border-radius: 16px; border: none; }}"
        )

        self._down = deque([0.0] * (self.HISTORY + 1), maxlen=self.HISTORY + 1)
        self._up   = deque([0.0] * (self.HISTORY + 1), maxlen=self.HISTORY + 1)
        self._down_rate = 0.0
        self._up_rate   = 0.0
        self._down_peak = 4096.0
        self._up_peak   = 4096.0
        self._scroll    = 0.0
        self._active    = False

        self._label_font = QFont(self.font())
        self._label_font.setPixelSize(11)

        self._anim_timer = QTimer(self)
        self._anim_timer.timeout.connect(self._advance)
        self._anim_timer.start(16)

    def set_active(self, active: bool) -> None:
        self._active = active
        self.update()

    def push_sample(self, down_rate: float, up_rate: float) -> None:
        self._down.append(down_rate)
        self._up.append(up_rate)
        self._down_rate = down_rate
        self._up_rate = up_rate
        self._down_peak = max(self._down_peak * 0.97, max(self._down), 4096.0)
        self._up_peak = max(self._up_peak * 0.97, max(self._up), 4096.0)
        self._scroll = 0.0

    def _advance(self) -> None:
        self._scroll = min(1.0, self._scroll + 16.0 / self.SAMPLE_MS)
        self.update()

    def _wave_points(self, samples, peak, pad_x, top, plot_w, plot_h, slot_w):
        pts = []
        for i, v in enumerate(samples):
            x = pad_x + i * slot_w - slot_w * self._scroll
            norm = min(1.0, v / peak) if peak > 0 else 0.0
            y = top + plot_h - norm * plot_h
            pts.append((x, y))
        return pts

    @staticmethod
    def _smooth_path(pts) -> QPainterPath:
        path = QPainterPath()
        path.moveTo(pts[0][0], pts[0][1])
        for i in range(1, len(pts)):
            x0, y0 = pts[i - 1]
            x1, y1 = pts[i]
            cx = (x0 + x1) / 2
            path.cubicTo(cx, y0, cx, y1, x1, y1)
        return path

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        pad_x = 16
        top = 32
        bottom_pad = 14
        plot_w = self.width() - 2 * pad_x
        plot_h = self.height() - top - bottom_pad
        slot_w = plot_w / (self.HISTORY - 1)

        if self._active:
            down_color, up_color = DOWN_COLOR, UP_COLOR
        else:
            down_color, up_color = TEXT_SECONDARY, IDLE

        painter.setClipRect(QRectF(pad_x, 0, plot_w, self.height()))
        for samples, peak, color_hex in (
            (self._down, self._down_peak, down_color),
            (self._up, self._up_peak, up_color),
        ):
            pts = self._wave_points(samples, peak, pad_x, top, plot_w, plot_h, slot_w)
            path = self._smooth_path(pts)

            fill = QPainterPath(path)
            fill.lineTo(pts[-1][0], top + plot_h)
            fill.lineTo(pts[0][0], top + plot_h)
            fill.closeSubpath()

            fill_color = QColor(color_hex)
            fill_color.setAlpha(26)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(fill_color)
            painter.drawPath(fill)

            pen = QPen(QColor(color_hex))
            pen.setWidthF(2.4)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(pen)
            painter.drawPath(path)
        painter.setClipping(False)

        painter.setFont(self._label_font)

        down_text = f"Download   {_format_rate(self._down_rate)}"
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(down_color))
        painter.drawEllipse(pad_x, 12, 7, 7)
        painter.setPen(QColor(TEXT_SECONDARY))
        painter.drawText(pad_x + 13, 20, down_text)

        up_text = f"Upload   {_format_rate(self._up_rate)}"
        up_text_w = painter.fontMetrics().horizontalAdvance(up_text)
        up_x = self.width() - pad_x - up_text_w - 13
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(up_color))
        painter.drawEllipse(up_x, 12, 7, 7)
        painter.setPen(QColor(TEXT_SECONDARY))
        painter.drawText(up_x + 13, 20, up_text)

        painter.end()


class ProxyPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NatPY Socks Server")
        self.setFixedWidth(380)

        self._config = ConfigStore()
        self._proxy: VPNSocks5Proxy | None = None
        self._thread: threading.Thread | None = None
        self._stopping = False

        self._auto_host = self._detect_default_host()

        self._last_down_bytes = 0
        self._last_up_bytes = 0
        self._last_sample_time = time.monotonic()

        self._build_ui()
        self._load_config()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(500)

    @staticmethod
    def _detect_default_host() -> str:
        try:
            return VPNSocks5Proxy._detect_listen_address()
        except Exception:
            return "0.0.0.0"

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 32, 28, 28)
        root.setSpacing(6)

        badge_row = QHBoxLayout()
        badge_row.setAlignment(Qt.AlignCenter)
        self._badge = ConnectionBadge()
        badge_row.addWidget(self._badge)
        root.addLayout(badge_row)

        root.addSpacing(18)

        self._graph = BandwidthGraph()
        root.addWidget(self._graph)

        root.addSpacing(20)

        self._host_edit = self._add_field(root, "IP Address")
        self._host_edit.editingFinished.connect(self._ensure_host_default)
        self._port_edit = self._add_field(root, "Port")
        self._port_edit.setText("9898")
        self._user_edit = self._add_field(root, "Username (optional)")
        self._pass_edit = self._add_field(root, "Password (optional)")
        self._pass_edit.setEchoMode(QLineEdit.Password)

        show_pass = QCheckBox("Show password")
        show_pass.toggled.connect(
            lambda checked: self._pass_edit.setEchoMode(
                QLineEdit.Normal if checked else QLineEdit.Password
            )
        )
        root.addWidget(show_pass)

        root.addSpacing(14)

        self._toggle_btn = QPushButton("Start Proxy")
        self._toggle_btn.setFixedHeight(48)
        self._toggle_btn.setFocusPolicy(Qt.NoFocus)
        self._toggle_btn.setCursor(Qt.PointingHandCursor)
        self._toggle_btn.clicked.connect(self._on_toggle)
        root.addWidget(self._toggle_btn)
        self._style_toggle_button(running=False)

    def _add_field(self, layout: QVBoxLayout, label_text: str) -> QLineEdit:
        label = QLabel(label_text)
        label.setProperty("role", "fieldLabel")
        edit = QLineEdit()
        layout.addWidget(label)
        layout.addWidget(edit)
        layout.addSpacing(10)
        return edit

    def _style_toggle_button(self, running: bool) -> None:
        color = DANGER if running else Initiate
        self._toggle_btn.setText("Stop Proxy" if running else "Start Proxy")
        self._toggle_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {color};
                color: #eeeeee;
                border: none;
                border-radius: 14px;
                font-size: 15px;
                font-weight: 700;
            }}
            QPushButton:disabled {{
                background-color: {IDLE};
            }}
            """
        )

    def _load_config(self) -> None:
        data = self._config.load()
        self._host_edit.setText(data.get("host") or self._auto_host)
        self._port_edit.setText(data.get("port", "9898"))
        self._user_edit.setText(data.get("username", ""))
        self._pass_edit.setText(data.get("password", ""))

    def _ensure_host_default(self) -> None:
        if not self._host_edit.text().strip():
            self._host_edit.setText(self._auto_host)

    def _on_toggle(self) -> None:
        if self._proxy is not None:
            self._stop_proxy()
        else:
            self._start_proxy()

    def _start_proxy(self) -> None:
        port_text = self._port_edit.text().strip()
        if not port_text.isdigit():
            QMessageBox.warning(self, "Invalid Port", "Please enter a valid port number.")
            return

        host = self._host_edit.text().strip() or self._auto_host
        username = self._user_edit.text().strip() or None
        password = self._pass_edit.text() or None

        self._config.save(
            self._host_edit.text().strip(),
            port_text,
            self._user_edit.text().strip(),
            self._pass_edit.text(),
        )

        proxy = VPNSocks5Proxy(
            host=host,
            port=int(port_text),
            username=username,
            password=password,
        )
        thread = threading.Thread(target=proxy.start, daemon=True)
        thread.start()

        self._proxy = proxy
        self._thread = thread
        self._last_down_bytes = 0
        self._last_up_bytes = 0
        self._last_sample_time = time.monotonic()
        self._toggle_btn.setEnabled(True)
        self._style_toggle_button(running=True)
        self._badge.set_running(True)
        self._graph.set_active(True)

    def _stop_proxy(self) -> None:
        if self._proxy is None:
            return
        self._proxy.stop()
        self._stopping = True
        self._toggle_btn.setEnabled(False)

    def _update_bandwidth_sample(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_sample_time
        if elapsed <= 0:
            return

        down_total = self._proxy.download_bytes
        up_total = self._proxy.upload_bytes

        down_rate = max(0.0, (down_total - self._last_down_bytes) / elapsed)
        up_rate = max(0.0, (up_total - self._last_up_bytes) / elapsed)

        self._last_down_bytes = down_total
        self._last_up_bytes = up_total
        self._last_sample_time = now

        self._graph.push_sample(down_rate, up_rate)

    def _tick(self) -> None:
        if self._proxy is None:
            return

        self._badge.set_count(self._proxy.active_users)
        self._update_bandwidth_sample()

        if self._stopping and self._thread is not None and not self._thread.is_alive():
            self._stopping = False
            self._proxy = None
            self._thread = None
            self._toggle_btn.setEnabled(True)
            self._style_toggle_button(running=False)
            self._badge.set_running(False)
            self._badge.set_count(0)
            self._graph.set_active(False)
            self._graph.push_sample(0.0, 0.0)

    def closeEvent(self, event) -> None:
        if self._proxy is not None:
            self._proxy.stop()
        event.accept()


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLESHEET)

    panel = ProxyPanel()
    panel.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
