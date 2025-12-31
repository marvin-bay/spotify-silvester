"""
PyQt6 UI for Spotify New Year playback.

Setup:
1) Install dependencies: pip install -r requirements.txt
2) Run: python main.py

The GUI can create and update .env for you. All settings are editable
from the UI and stored once you save them.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import threading
import time
import webbrowser
from urllib.parse import parse_qs, urlparse

try:
    from PyQt6 import QtCore, QtGui, QtWidgets, QtNetwork, QtSvg
except ImportError as exc:  # pragma: no cover - runtime guard
    raise RuntimeError(
        "PyQt6 is not installed. Install with: pip install -r requirements.txt"
    ) from exc

from config import AppConfig, ROOT_DIR, load_config, save_env_value
from songs import SONG_SCHEDULES, SongSchedule, TEST_LABEL
from spotify_service import (
    create_auth_manager,
    create_spotify_client,
    ensure_active_device,
    exchange_code_for_token,
    queue_and_play_next,
)

SPOTIFY_DASHBOARD_URL = "https://developer.spotify.com/dashboard"
DEFAULT_REDIRECT_URI = "https://127.0.0.1:8888/callback"
DEFAULT_CERT_PATH = Path(".certs/spotify_localhost.pem")
DEFAULT_KEY_PATH = Path(".certs/spotify_localhost.key")
ALBUM_ART_SIZE = 80
SEARCH_ALBUM_ART_SIZE = 56
SEARCH_ITEM_HEIGHT = 120
TEST_PLAY_DELAY_SECONDS = 10


def format_datetime(value: datetime) -> str:
    return value.strftime("%H:%M:%S")


def clean_value(raw_value: str) -> str | None:
    raw = raw_value.strip()
    if not raw or raw.startswith("PUT_"):
        return None
    return raw


def extract_auth_code(raw_value: str) -> str:
    raw = raw_value.strip()
    if not raw:
        raise ValueError("Missing auth code")

    if raw.startswith("code="):
        return raw.split("code=", 1)[1].split("&", 1)[0]

    if "code=" in raw:
        parsed = urlparse(raw)
        query = parse_qs(parsed.query)
        if "code" in query and query["code"]:
            return query["code"][0]
        return raw.split("code=", 1)[1].split("&", 1)[0]

    return raw


def track_id_from_uri(uri: str) -> str | None:
    raw = uri.strip()
    if raw.startswith("spotify:track:"):
        return raw.split(":")[-1]
    if "open.spotify.com/track/" in raw:
        parsed = urlparse(raw)
        parts = parsed.path.strip("/").split("/")
        if "track" in parts:
            idx = parts.index("track")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return None


def schedule_time_label(schedule: SongSchedule) -> str:
    display_fn = getattr(schedule, "display_time", None)
    if callable(display_fn):
        try:
            return display_fn()
        except Exception:
            pass
    hour = getattr(schedule, "hour", 0)
    minute = getattr(schedule, "minute", 0)
    second = getattr(schedule, "second", 0)
    return f"{hour:02d}:{minute:02d}:{second:02d}"


def parse_redirect_uri(redirect_uri: str) -> tuple[str, str, int, str]:
    parsed = urlparse(redirect_uri.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Redirect URI must start with http:// or https://")
    if not parsed.hostname:
        raise ValueError("Redirect URI must include a hostname")
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    path = parsed.path or "/"
    return parsed.scheme, parsed.hostname, port, path


def resolve_path(raw_path: str, fallback: Path) -> Path:
    value = raw_path.strip() or str(fallback)
    path = Path(value)
    if not path.is_absolute():
        path = ROOT_DIR / path
    return path


def ensure_tls_cert_files(cert_path: Path, key_path: Path) -> None:
    if cert_path.exists() and key_path.exists():
        return
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    openssl_bin = shutil.which("openssl")
    if not openssl_bin:
        raise RuntimeError("OpenSSL not found. Install it to generate a local HTTPS cert.")

    base_cmd = [
        openssl_bin,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        "365",
        "-subj",
        "/CN=localhost",
    ]

    with_san = base_cmd + [
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    result = subprocess.run(with_san, capture_output=True, text=True)
    if result.returncode == 0:
        return

    fallback = subprocess.run(base_cmd, capture_output=True, text=True)
    if fallback.returncode != 0:
        raise RuntimeError(f"OpenSSL failed: {fallback.stderr.strip()}")


class CallbackServerThread(QtCore.QThread):
    code_received = QtCore.pyqtSignal(str)
    error_received = QtCore.pyqtSignal(str)
    status = QtCore.pyqtSignal(str)

    def __init__(
        self,
        scheme: str,
        host: str,
        port: int,
        path: str,
        cert_path: Path | None,
        key_path: Path | None,
    ) -> None:
        super().__init__()
        self.scheme = scheme
        self.host = host
        self.port = port
        self.path = path
        self.cert_path = cert_path
        self.key_path = key_path
        self.httpd: HTTPServer | None = None

    def _make_handler(self):
        parent = self

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
                parsed = urlparse(self.path)
                if parsed.path != parent.path:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not Found")
                    return

                query = parse_qs(parsed.query)
                code = query.get("code", [None])[0]
                error = query.get("error", [None])[0]

                if error:
                    parent.error_received.emit(error)
                    self._respond_ok("Spotify auth failed. You can close this tab.")
                    parent.request_shutdown()
                    return

                if not code:
                    parent.error_received.emit("Missing auth code in callback.")
                    self._respond_ok("Missing code. You can close this tab.")
                    parent.request_shutdown()
                    return

                parent.code_received.emit(code)
                self._respond_ok("Auth code received. You can close this tab.")
                parent.request_shutdown()

            def log_message(self, format, *args) -> None:  # noqa: A002
                return

            def _respond_ok(self, message: str) -> None:
                body = (
                    "<html><head>"
                    "<script>"
                    "setTimeout(function(){ window.close(); }, 300);"
                    "</script>"
                    "</head><body>"
                    "<h2>Spotify auth complete</h2>"
                    f"<p>{message}</p>"
                    "<p>You can close this tab if it stays open.</p>"
                    "</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return CallbackHandler

    def _shutdown(self) -> None:
        if self.httpd:
            self.httpd.shutdown()

    def request_shutdown(self) -> None:
        threading.Thread(target=self._shutdown, daemon=True).start()

    def stop(self) -> None:
        self._shutdown()

    def run(self) -> None:
        try:
            server = HTTPServer((self.host, self.port), self._make_handler())
            if self.scheme == "https":
                if not self.cert_path or not self.key_path:
                    raise RuntimeError("Missing TLS cert/key paths for HTTPS callback.")
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
                server.socket = context.wrap_socket(server.socket, server_side=True)

            self.httpd = server
            self.status.emit(f"Callback server listening on {self.scheme}://{self.host}:{self.port}")
            server.serve_forever(poll_interval=0.2)
        except Exception as exc:  # pragma: no cover - UI thread surface
            self.error_received.emit(str(exc))
        finally:
            if self.httpd:
                self.httpd.server_close()
class CodeExchangeThread(QtCore.QThread):
    success = QtCore.pyqtSignal(object)
    failure = QtCore.pyqtSignal(str)
    status = QtCore.pyqtSignal(str)

    def __init__(self, auth_manager, code: str) -> None:
        super().__init__()
        self.auth_manager = auth_manager
        self.code = code

    def run(self) -> None:
        try:
            self.status.emit("Exchanging auth code for token...")
            exchange_code_for_token(self.auth_manager, self.code)
            client = create_spotify_client(self.auth_manager)
            self.status.emit("Authentication successful.")
            self.success.emit(client)
        except Exception as exc:  # pragma: no cover - UI thread surface
            self.failure.emit(str(exc))


class PlaybackThread(QtCore.QThread):
    status = QtCore.pyqtSignal(str)
    failure = QtCore.pyqtSignal(str)
    finished_ok = QtCore.pyqtSignal()

    def __init__(self, client, schedule: SongSchedule, target_time: datetime) -> None:
        super().__init__()
        self.client = client
        self.schedule = schedule
        self.target_time = target_time

    def run(self) -> None:
        try:
            target = self.target_time
            self.status.emit(f"Waiting until {format_datetime(target)}")
            while datetime.now() < target:
                if self.isInterruptionRequested():
                    self.status.emit("Playback cancelled.")
                    return
                time.sleep(0.1)
            ensure_active_device(self.client)
            queue_and_play_next(self.client, self.schedule.uri)
            self.status.emit("Playback command sent.")
            self.finished_ok.emit()
        except Exception as exc:  # pragma: no cover - UI thread surface
            self.failure.emit(str(exc))


class TrackInfoThread(QtCore.QThread):
    success = QtCore.pyqtSignal(list)
    failure = QtCore.pyqtSignal(str)
    status = QtCore.pyqtSignal(str)

    def __init__(self, client, schedules: list[SongSchedule]) -> None:
        super().__init__()
        self.client = client
        self.schedules = schedules

    def run(self) -> None:
        try:
            self.status.emit("Fetching track metadata...")
            track_map = self._fetch_tracks()
            results = []
            for schedule in self.schedules:
                results.append(self._fetch_schedule_info(schedule, track_map))
            self.success.emit(results)
        except Exception as exc:  # pragma: no cover - UI thread surface
            self.failure.emit(str(exc))

    def _fetch_tracks(self) -> dict:
        track_ids: list[str] = []
        seen: set[str] = set()
        for schedule in self.schedules:
            track_id = track_id_from_uri(schedule.uri)
            if track_id and track_id not in seen:
                track_ids.append(track_id)
                seen.add(track_id)

        track_map: dict[str, dict] = {}
        for start in range(0, len(track_ids), 50):
            batch = track_ids[start : start + 50]
            if not batch:
                continue
            data = self.client.tracks(batch)
            for track in data.get("tracks", []):
                if track and track.get("id"):
                    track_map[track["id"]] = track
        return track_map

    def _fetch_schedule_info(self, schedule: SongSchedule, track_map: dict) -> dict:
        track_id = track_id_from_uri(schedule.uri)
        track = track_map.get(track_id) if track_id else None
        if not track:
            return {
                "schedule": schedule,
                "title": schedule.label or schedule.uri,
                "artists": "Unknown artist",
                "image_url": None,
            }

        title = track.get("name") or schedule.label or schedule.uri
        artists = ", ".join(
            artist.get("name", "")
            for artist in track.get("artists", [])
            if artist.get("name")
        )
        if not artists:
            artists = "Unknown artist"

        images = track.get("album", {}).get("images", [])
        return {
            "schedule": schedule,
            "title": title,
            "artists": artists,
            "image_url": images[0].get("url") if images else None,
        }


class TimeInputDialog(QtWidgets.QDialog):
    def __init__(self, parent: QtWidgets.QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Schedule time")

        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(12)

        hint = QtWidgets.QLabel("Choose the time (HH:MM:SS) for playback.")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        form = QtWidgets.QFormLayout()
        self.hour_input = QtWidgets.QSpinBox()
        self.hour_input.setRange(0, 23)
        self.minute_input = QtWidgets.QSpinBox()
        self.minute_input.setRange(0, 59)
        self.second_input = QtWidgets.QSpinBox()
        self.second_input.setRange(0, 59)
        form.addRow("Hour", self.hour_input)
        form.addRow("Minute", self.minute_input)
        form.addRow("Second", self.second_input)
        layout.addLayout(form)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok
            | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def time_values(self) -> tuple[int, int, int]:
        return self.hour_input.value(), self.minute_input.value(), self.second_input.value()


class SongSearchDialog(QtWidgets.QDialog):
    def __init__(self, parent: "MainWindow", client) -> None:
        super().__init__(parent)
        self.parent_window = parent
        self.client = client
        self.selected_track: dict | None = None

        self.setWindowTitle("Search Spotify")

        layout = QtWidgets.QVBoxLayout(self)
        layout.setSpacing(12)

        search_row = QtWidgets.QHBoxLayout()
        self.search_input = QtWidgets.QLineEdit()
        self.search_input.setPlaceholderText("Search for songs or artists")
        self.search_button = QtWidgets.QPushButton("Search")
        self.search_button.clicked.connect(self.perform_search)
        self.search_input.returnPressed.connect(self.perform_search)
        search_row.addWidget(self.search_input, 1)
        search_row.addWidget(self.search_button)
        layout.addLayout(search_row)

        self.results_list = QtWidgets.QListWidget()
        self.results_list.setSelectionMode(
            QtWidgets.QAbstractItemView.SelectionMode.SingleSelection
        )
        self.results_list.setIconSize(
            QtCore.QSize(SEARCH_ALBUM_ART_SIZE, SEARCH_ALBUM_ART_SIZE)
        )
        self.results_list.setSpacing(6)
        self.results_list.setUniformItemSizes(False)
        layout.addWidget(self.results_list, 1)

        self.status_label = QtWidgets.QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        buttons = QtWidgets.QDialogButtonBox()
        self.add_button = QtWidgets.QPushButton("Add selected")
        self.add_button.setEnabled(False)
        self.add_button.clicked.connect(self.accept_selection)
        buttons.addButton(self.add_button, QtWidgets.QDialogButtonBox.ButtonRole.AcceptRole)
        cancel_button = QtWidgets.QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        buttons.addButton(cancel_button, QtWidgets.QDialogButtonBox.ButtonRole.RejectRole)
        layout.addWidget(buttons)

        self.results_list.currentItemChanged.connect(self.on_selection_changed)

        self.resize(760, 560)

    def on_selection_changed(self) -> None:
        self.add_button.setEnabled(self.results_list.currentItem() is not None)

    def perform_search(self) -> None:
        query = self.search_input.text().strip()
        if not query:
            self.status_label.setText("Enter a search term.")
            return

        self.status_label.setText("Searching...")
        QtWidgets.QApplication.processEvents()
        results = self.client.search(q=query, type="track", limit=20)
        tracks = results.get("tracks", {}).get("items", [])
        self.populate_results(tracks)

    def populate_results(self, tracks: list[dict]) -> None:
        self.results_list.clear()
        if not tracks:
            self.status_label.setText("No results.")
            return

        for track in tracks:
            title = track.get("name", "Unknown track")
            artists = ", ".join(
                artist.get("name", "")
                for artist in track.get("artists", [])
                if artist.get("name")
            )
            if not artists:
                artists = "Unknown artist"
            image_url = None
            images = track.get("album", {}).get("images", [])
            if images:
                image_url = images[0].get("url")
            uri = track.get("uri", "")

            item = QtWidgets.QListWidgetItem()
            widget, cover_label = self.parent_window.build_track_item_widget(
                title,
                f"{artists} • Select to schedule",
                image_url,
                cover_size=SEARCH_ALBUM_ART_SIZE,
            )
            widget.setMinimumHeight(SEARCH_ITEM_HEIGHT)
            item.setSizeHint(
                QtCore.QSize(0, max(SEARCH_ITEM_HEIGHT, SEARCH_ALBUM_ART_SIZE + 32))
            )
            item.setData(
                QtCore.Qt.ItemDataRole.UserRole,
                {"title": title, "artists": artists, "uri": uri},
            )
            self.results_list.addItem(item)
            self.results_list.setItemWidget(item, widget)

            if image_url:
                self.parent_window.fetch_cover(image_url, cover_label)

        self.status_label.setText(f"Found {len(tracks)} tracks.")

    def accept_selection(self) -> None:
        item = self.results_list.currentItem()
        if item is None:
            return
        self.selected_track = item.data(QtCore.Qt.ItemDataRole.UserRole)
        self.accept()


class MainWindow(QtWidgets.QWidget):
    def __init__(self, config: AppConfig, app_icon: QtGui.QIcon) -> None:
        super().__init__()
        self.config = config
        self.app_icon = app_icon
        self.default_cover_pixmap = QtGui.QPixmap(
            str(ROOT_DIR / "Spotify_logo_without_text.svg.png")
        )
        self.client = None
        self.auth_manager = None
        self.exchange_thread: CodeExchangeThread | None = None
        self.callback_thread: CallbackServerThread | None = None
        self.track_info_thread: TrackInfoThread | None = None
        self.playback_thread: PlaybackThread | None = None
        self.active_target: datetime | None = None
        self.active_schedule: SongSchedule | None = None
        self.cover_manager = QtNetwork.QNetworkAccessManager(self)
        self.cover_cache: dict[str, QtGui.QPixmap] = {}
        self.cover_requests: dict[QtNetwork.QNetworkReply, QtWidgets.QLabel] = {}

        self.setWindowTitle("Silvester Spotify Scheduler")
        self.setWindowIcon(self.app_icon)

        self.setObjectName("root")
        self.root_layout = QtWidgets.QVBoxLayout(self)
        self.root_layout.setContentsMargins(16, 12, 16, 16)
        self.root_layout.setSpacing(12)

        self.header = QtWidgets.QWidget()
        self.header.setObjectName("header")
        header_layout = QtWidgets.QHBoxLayout(self.header)
        header_layout.setContentsMargins(16, 12, 16, 12)
        header_layout.setSpacing(12)

        logo_label = QtWidgets.QLabel()
        logo_label.setFixedSize(42, 42)
        if not self.default_cover_pixmap.isNull():
            logo_label.setPixmap(
                self.default_cover_pixmap.scaled(
                    42,
                    42,
                    QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                    QtCore.Qt.TransformationMode.SmoothTransformation,
                )
            )
        header_layout.addWidget(logo_label)

        title_block = QtWidgets.QVBoxLayout()
        app_title = QtWidgets.QLabel("Silvester Spotify Scheduler")
        app_title.setObjectName("appTitle")
        title_block.addWidget(app_title)

        app_subtitle = QtWidgets.QLabel("Party-ready playback with precise timing")
        app_subtitle.setObjectName("appSubtitle")
        title_block.addWidget(app_subtitle)

        header_layout.addLayout(title_block)
        header_layout.addStretch(1)

        self.root_layout.addWidget(self.header)

        self.stack = QtWidgets.QStackedWidget()
        self.stack.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Preferred,
        )
        self.scroll_area = QtWidgets.QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setFrameShape(QtWidgets.QFrame.Shape.NoFrame)
        self.scroll_area.setHorizontalScrollBarPolicy(
            QtCore.Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.scroll_area.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarPolicy.ScrollBarAsNeeded
        )
        self.scroll_area.setWidget(self.stack)
        self.root_layout.addWidget(self.scroll_area, 1)

        self.setup_page = QtWidgets.QWidget()
        self.selection_page = QtWidgets.QWidget()
        self.stack.addWidget(self.setup_page)
        self.stack.addWidget(self.selection_page)

        setup_layout = QtWidgets.QVBoxLayout(self.setup_page)
        setup_layout.setContentsMargins(0, 0, 0, 0)
        setup_layout.setSpacing(12)
        setup_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        title = QtWidgets.QLabel("Setup")
        title.setObjectName("sectionTitle")
        setup_layout.addWidget(title)

        self.setup_tabs = QtWidgets.QTabWidget()
        self.setup_tabs.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Fixed,
        )
        setup_layout.addWidget(self.setup_tabs)

        self.basic_tab = QtWidgets.QWidget()
        basic_layout = QtWidgets.QVBoxLayout(self.basic_tab)
        basic_layout.setContentsMargins(16, 16, 16, 16)
        basic_layout.setSpacing(12)
        basic_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        instructions = QtWidgets.QLabel(
            "1) Configure settings in Advanced (first time)\n"
            "2) Open the login page\n"
            "3) Approve login in your browser"
        )
        instructions.setWordWrap(True)
        basic_layout.addWidget(instructions)

        settings_group = QtWidgets.QGroupBox("Settings")
        settings_layout = QtWidgets.QFormLayout(settings_group)
        settings_layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow
        )

        self.client_id_input = QtWidgets.QLineEdit()
        self.client_id_input.setText(self.config.spotify_client_id or "")
        self._configure_input_field(self.client_id_input)
        client_id_row = self._wrap_field_with_button(
            self.client_id_input,
            "Open",
            "Open Spotify Dashboard",
            self.open_spotify_dashboard,
        )
        settings_layout.addRow("Client ID", client_id_row)

        self.client_secret_input = QtWidgets.QLineEdit()
        self.client_secret_input.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.client_secret_input.setText(self.config.spotify_client_secret or "")
        self._configure_input_field(self.client_secret_input)
        client_secret_row = self._wrap_field_with_button(
            self.client_secret_input,
            "Open",
            "Open Spotify Dashboard",
            self.open_spotify_dashboard,
        )
        settings_layout.addRow("Client Secret", client_secret_row)

        self.redirect_uri_input = QtWidgets.QLineEdit()
        redirect_default = self.config.spotify_redirect_uri or DEFAULT_REDIRECT_URI
        self.redirect_uri_input.setText(redirect_default)
        self._configure_input_field(self.redirect_uri_input)
        redirect_row = self._wrap_field_with_button(
            self.redirect_uri_input,
            "Open",
            "Open Spotify Dashboard",
            self.open_spotify_dashboard,
        )
        settings_layout.addRow("Redirect URI", redirect_row)

        self.cache_path_input = QtWidgets.QLineEdit()
        self.cache_path_input.setText(str(self.config.spotify_cache_path))
        self._configure_input_field(self.cache_path_input)
        settings_layout.addRow("Cache Path", self.cache_path_input)

        self.cert_path_input = QtWidgets.QLineEdit()
        self.cert_path_input.setText(str(self.config.spotify_cert_path))
        self._configure_input_field(self.cert_path_input)
        settings_layout.addRow("TLS Cert Path", self.cert_path_input)

        self.key_path_input = QtWidgets.QLineEdit()
        self.key_path_input.setText(str(self.config.spotify_key_path))
        self._configure_input_field(self.key_path_input)
        settings_layout.addRow("TLS Key Path", self.key_path_input)

        self.generate_cert_button = QtWidgets.QPushButton("Generate TLS cert")
        self.generate_cert_button.clicked.connect(self.generate_tls_cert)
        settings_layout.addRow(self.generate_cert_button)

        self.debug_checkbox = QtWidgets.QCheckBox("Enable debug logging")
        self.debug_checkbox.setChecked(self.config.debug)
        settings_layout.addRow(self.debug_checkbox)

        self.test_mode_checkbox = QtWidgets.QCheckBox("Enable test mode (+10s test song)")
        self.test_mode_checkbox.setChecked(self.config.spotify_test_mode)
        settings_layout.addRow(self.test_mode_checkbox)

        self.save_settings_button = QtWidgets.QPushButton("Save settings to .env")
        self.save_settings_button.clicked.connect(self.save_settings)
        settings_layout.addRow(self.save_settings_button)

        auth_group = QtWidgets.QGroupBox("Authentication")
        auth_layout = QtWidgets.QVBoxLayout(auth_group)

        self.open_login_button = QtWidgets.QPushButton("Open login page")
        self.open_login_button.clicked.connect(self.open_login_page)
        auth_layout.addWidget(self.open_login_button)

        self.login_url_label = QtWidgets.QLabel("")
        self.login_url_label.setWordWrap(True)
        auth_layout.addWidget(self.login_url_label)

        basic_layout.addWidget(auth_group)
        self.setup_tabs.addTab(self.basic_tab, "Setup")

        self.advanced_tab = QtWidgets.QWidget()
        advanced_layout = QtWidgets.QVBoxLayout(self.advanced_tab)
        advanced_layout.setContentsMargins(16, 16, 16, 16)
        advanced_layout.setSpacing(12)
        advanced_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        advanced_layout.addWidget(settings_group)

        manual_group = QtWidgets.QGroupBox("Manual auth code (fallback)")
        manual_layout = QtWidgets.QVBoxLayout(manual_group)
        manual_hint = QtWidgets.QLabel(
            "Only needed if the callback cannot reach the app."
        )
        manual_hint.setWordWrap(True)
        manual_layout.addWidget(manual_hint)

        self.code_input = QtWidgets.QLineEdit()
        self.code_input.setPlaceholderText(
            "Paste auth code or full redirect URL from Spotify"
        )
        if self.config.spotify_auth_code:
            self.code_input.setText(self.config.spotify_auth_code)
        self._configure_input_field(self.code_input)
        self.code_input.setEnabled(False)
        manual_layout.addWidget(self.code_input)

        self.submit_code_button = QtWidgets.QPushButton("Submit auth code")
        self.submit_code_button.setEnabled(False)
        self.submit_code_button.clicked.connect(self.submit_auth_code)
        manual_layout.addWidget(self.submit_code_button)

        advanced_layout.addWidget(manual_group)
        self.setup_tabs.addTab(self.advanced_tab, "Advanced")

        selection_layout = QtWidgets.QVBoxLayout(self.selection_page)
        selection_layout.setContentsMargins(8, 0, 8, 8)
        selection_layout.setSpacing(12)
        selection_layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)

        selection_title = QtWidgets.QLabel("Songauswahl")
        selection_title.setObjectName("sectionTitle")
        selection_layout.addWidget(selection_title)

        self.countdown_label = QtWidgets.QLabel("Countdown: --:--:--")
        self.countdown_label.setObjectName("countdown")
        countdown_font = QtGui.QFont()
        countdown_font.setPointSize(28)
        countdown_font.setBold(True)
        self.countdown_label.setFont(countdown_font)
        selection_layout.addWidget(self.countdown_label)

        search_group = QtWidgets.QGroupBox("Add song from Spotify")
        search_layout = QtWidgets.QVBoxLayout(search_group)
        search_hint = QtWidgets.QLabel(
            "Search Spotify and add a track to songs.py with a scheduled time."
        )
        search_hint.setWordWrap(True)
        search_layout.addWidget(search_hint)
        self.search_song_button = QtWidgets.QPushButton("Search Spotify")
        self.search_song_button.setEnabled(False)
        self.search_song_button.clicked.connect(self.open_song_search)
        search_layout.addWidget(self.search_song_button)
        selection_layout.addWidget(search_group)

        self.song_list = QtWidgets.QListWidget()
        self.song_list.setEnabled(False)
        self.song_list.currentItemChanged.connect(self.on_song_selected)
        self.song_list.setIconSize(QtCore.QSize(ALBUM_ART_SIZE, ALBUM_ART_SIZE))
        self.song_list.setSpacing(6)
        self.song_list.setUniformItemSizes(False)
        self.song_list.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.SingleSelection)
        selection_layout.addWidget(self.song_list)

        self.selection_label = QtWidgets.QLabel("Selected: none")
        self.selection_label.setObjectName("selectionLabel")
        selection_layout.addWidget(self.selection_label)

        self.schedule_button = QtWidgets.QPushButton("Start selected schedule")
        self.schedule_button.setEnabled(False)
        self.schedule_button.clicked.connect(self.start_schedule)
        selection_layout.addWidget(self.schedule_button)

        self.status_label = QtWidgets.QLabel("Status: idle")
        self.status_label.setWordWrap(True)
        self.root_layout.addWidget(self.status_label)

        self.footer = QtWidgets.QWidget()
        self.footer.setObjectName("footer")
        footer_layout = QtWidgets.QHBoxLayout(self.footer)
        footer_layout.setContentsMargins(8, 8, 8, 8)
        footer_layout.setSpacing(8)
        footer_layout.addStretch(1)

        self.github_icon_label = QtWidgets.QLabel()
        self.github_icon_label.setObjectName("githubBadge")
        self.github_icon_label.setFixedSize(22, 22)
        self.github_icon_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        github_svg_path = ROOT_DIR / "github-mark-white.svg"
        github_png_path = ROOT_DIR / "github-mark-white.png"
        github_pixmap = QtGui.QPixmap(14, 14)
        github_pixmap.fill(QtCore.Qt.GlobalColor.transparent)
        renderer = QtSvg.QSvgRenderer(str(github_svg_path))
        if renderer.isValid():
            painter = QtGui.QPainter(github_pixmap)
            renderer.render(painter)
            painter.end()
            self.github_icon_label.setPixmap(github_pixmap)
        else:
            fallback_pixmap = QtGui.QPixmap(str(github_png_path))
            if not fallback_pixmap.isNull():
                self.github_icon_label.setPixmap(
                    fallback_pixmap.scaled(
                        14,
                        14,
                        QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                        QtCore.Qt.TransformationMode.SmoothTransformation,
                    )
                )
            else:
                self.github_icon_label.setText("GH")
        footer_layout.addWidget(self.github_icon_label)

        footer_link = QtWidgets.QLabel(
            '<a href="https://github.com/marvin-bay">github.com/marvin-bay</a>'
        )
        footer_link.setObjectName("footerLink")
        footer_link.setTextInteractionFlags(
            QtCore.Qt.TextInteractionFlag.TextBrowserInteraction
        )
        footer_link.setOpenExternalLinks(True)
        footer_layout.addWidget(footer_link)
        self.root_layout.addWidget(self.footer)

        self.stack.setCurrentWidget(self.setup_page)

        self.countdown_timer = QtCore.QTimer(self)
        self.countdown_timer.setInterval(500)
        self.countdown_timer.timeout.connect(self.update_countdown)

        self.basic_window_size = QtCore.QSize(620, 420)
        self.advanced_window_size = QtCore.QSize(900, 680)
        self.selection_window_size = QtCore.QSize(700, 560)
        self.setup_tabs.currentChanged.connect(self.on_setup_tab_changed)
        self.stack.currentChanged.connect(self.on_stack_changed)
        self.update_window_size()

        QtCore.QTimer.singleShot(0, self.update_window_size)

    def showEvent(self, event) -> None:  # noqa: N802 - Qt naming
        super().showEvent(event)
        QtCore.QTimer.singleShot(0, self.update_window_size)

    def _configure_input_field(self, line_edit: QtWidgets.QLineEdit) -> None:
        line_edit.setMinimumWidth(420)
        line_edit.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding,
            QtWidgets.QSizePolicy.Policy.Fixed,
        )

    def _wrap_field_with_button(
        self,
        line_edit: QtWidgets.QLineEdit,
        button_text: str,
        tooltip: str,
        callback,
    ) -> QtWidgets.QWidget:
        container = QtWidgets.QWidget()
        row_layout = QtWidgets.QHBoxLayout(container)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.addWidget(line_edit, 1)
        button = QtWidgets.QPushButton(button_text)
        button.setToolTip(tooltip)
        button.clicked.connect(callback)
        row_layout.addWidget(button)
        return container

    def load_track_metadata(self) -> None:
        if self.client is None:
            return
        if self.track_info_thread and self.track_info_thread.isRunning():
            return

        self.song_list.clear()
        self.song_list.addItem("Loading songs...")
        self.song_list.setEnabled(False)
        self.schedule_button.setEnabled(False)

        schedules = self.get_active_schedules()
        self.track_info_thread = TrackInfoThread(self.client, schedules)
        self.track_info_thread.status.connect(self._set_status)
        self.track_info_thread.success.connect(self.on_track_metadata_loaded)
        self.track_info_thread.failure.connect(self.on_track_metadata_error)
        self.track_info_thread.start()

    def get_active_schedules(self) -> list[SongSchedule]:
        if self.config.spotify_test_mode:
            return list(SONG_SCHEDULES)
        return [schedule for schedule in SONG_SCHEDULES if schedule.label != TEST_LABEL]

    def on_track_metadata_loaded(self, track_items: list[dict]) -> None:
        self.populate_song_list(track_items)
        self._set_status("Song data loaded.")

    def on_track_metadata_error(self, message: str) -> None:
        self.song_list.clear()
        self.song_list.setEnabled(True)
        self._set_status(f"Song load failed: {message}")
        self._show_message("Song load failed", message)

    def populate_song_list(self, track_items: list[dict]) -> None:
        self.song_list.clear()
        for info in track_items:
            schedule = info["schedule"]
            title = info["title"]
            artists = info["artists"]
            if self.config.spotify_test_mode and schedule.label == TEST_LABEL:
                time_label = f"+{TEST_PLAY_DELAY_SECONDS}s test"
            else:
                time_label = schedule_time_label(schedule)
            item = QtWidgets.QListWidgetItem()
            widget, cover_label = self.build_track_item_widget(
                title,
                f"{artists} • {time_label}",
                info.get("image_url"),
            )
            item.setSizeHint(QtCore.QSize(0, ALBUM_ART_SIZE + 16))
            if schedule.label:
                item.setToolTip(schedule.label)
            item.setData(QtCore.Qt.ItemDataRole.UserRole, schedule)
            item.setData(
                QtCore.Qt.ItemDataRole.UserRole + 1,
                {
                    "title": title,
                    "artists": artists,
                    "time_label": time_label,
                    "image_url": info.get("image_url"),
                },
            )
            self.song_list.addItem(item)
            self.song_list.setItemWidget(item, widget)

            image_url = info.get("image_url")
            if image_url:
                self.fetch_cover(image_url, cover_label)

        self.song_list.setEnabled(True)
        self.schedule_button.setEnabled(True)

    def build_track_item_widget(
        self,
        title: str,
        meta_text: str,
        image_url: str | None,
        cover_size: int = ALBUM_ART_SIZE,
    ) -> tuple[QtWidgets.QWidget, QtWidgets.QLabel]:
        widget = QtWidgets.QWidget()
        widget_layout = QtWidgets.QHBoxLayout(widget)
        widget_layout.setContentsMargins(8, 6, 8, 6)
        widget_layout.setSpacing(12)

        cover_label = QtWidgets.QLabel()
        cover_label.setFixedSize(cover_size, cover_size)
        cover_label.setObjectName("coverLabel")

        cover_pixmap = None
        if image_url and image_url in self.cover_cache:
            cover_pixmap = self.cover_cache[image_url]
        elif not self.default_cover_pixmap.isNull():
            cover_pixmap = self.default_cover_pixmap

        if cover_pixmap is not None:
            scaled = cover_pixmap.scaled(
                cover_size,
                cover_size,
                QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                QtCore.Qt.TransformationMode.SmoothTransformation,
            )
            cover_label.setPixmap(scaled)

        widget_layout.addWidget(cover_label)

        text_block = QtWidgets.QVBoxLayout()
        title_label = QtWidgets.QLabel(title)
        title_label.setObjectName("songTitle")
        title_label.setWordWrap(True)
        text_block.addWidget(title_label)

        meta_label = QtWidgets.QLabel(meta_text)
        meta_label.setObjectName("songMeta")
        meta_label.setWordWrap(True)
        text_block.addWidget(meta_label)

        widget_layout.addLayout(text_block, 1)
        return widget, cover_label

    def fetch_cover(self, image_url: str, target_label: QtWidgets.QLabel) -> None:
        cached = self.cover_cache.get(image_url)
        if cached is not None:
            target_size = target_label.size()
            scaled = cached.scaled(
                target_size.width(),
                target_size.height(),
                QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                QtCore.Qt.TransformationMode.SmoothTransformation,
            )
            target_label.setPixmap(scaled)
            return

        request = QtNetwork.QNetworkRequest(QtCore.QUrl(image_url))
        request.setRawHeader(b"User-Agent", b"spotify-silvester/1.0")
        reply = self.cover_manager.get(request)
        self.cover_requests[reply] = target_label
        reply.finished.connect(lambda r=reply: self.on_cover_reply(r))

    def on_cover_reply(self, reply: QtNetwork.QNetworkReply) -> None:
        target_label = self.cover_requests.pop(reply, None)
        if target_label is None:
            reply.deleteLater()
            return

        if reply.error() == QtNetwork.QNetworkReply.NetworkError.NoError:
            data = reply.readAll()
            pixmap = QtGui.QPixmap()
            if pixmap.loadFromData(bytes(data)):
                self.cover_cache[str(reply.url().toString())] = pixmap
                target_size = target_label.size()
                scaled = pixmap.scaled(
                    target_size.width(),
                    target_size.height(),
                    QtCore.Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                    QtCore.Qt.TransformationMode.SmoothTransformation,
                )
                target_label.setPixmap(scaled)
        reply.deleteLater()

    def _set_status(self, message: str) -> None:
        if self.config.debug:
            print(f"[DEBUG] {message}")
        self.status_label.setText(f"Status: {message}")

    def _show_message(self, title: str, message: str) -> None:
        box = QtWidgets.QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(message)
        box.setWindowIcon(self.app_icon)
        box.setIconPixmap(self.app_icon.pixmap(72, 72))
        box.setStandardButtons(QtWidgets.QMessageBox.StandardButton.Ok)
        box.exec()

    def bring_to_front(self) -> None:
        self.show()
        self.raise_()
        self.activateWindow()

    def on_setup_tab_changed(self) -> None:
        self.update_window_size()

    def on_stack_changed(self) -> None:
        self.update_window_size()

    def update_tab_heights(self) -> None:
        if self.stack.currentWidget() != self.setup_page:
            return
        current = self.setup_tabs.currentWidget()
        if current is None:
            return
        tab_bar_height = self.setup_tabs.tabBar().sizeHint().height()
        content_height = current.sizeHint().height()
        target_height = tab_bar_height + content_height + 24
        self.setup_tabs.setFixedHeight(target_height)

    def update_window_size(self) -> None:
        self.update_tab_heights()
        if self.stack.currentWidget() == self.selection_page:
            target_size = self.selection_window_size
        elif self.setup_tabs.currentWidget() == self.advanced_tab:
            target_size = self.advanced_window_size
        else:
            target_size = self.basic_window_size

        current_page = self.stack.currentWidget()
        stack_hint = current_page.sizeHint() if current_page else QtCore.QSize()
        stack_height = stack_hint.height()
        if stack_height:
            self.stack.setMinimumHeight(stack_height)
        content_width = max(
            self.header.sizeHint().width(),
            stack_hint.width(),
            self.status_label.sizeHint().width(),
            self.footer.sizeHint().width(),
        )
        min_button_width = max(
            [
                self.open_login_button.sizeHint().width(),
                self.generate_cert_button.sizeHint().width(),
                self.save_settings_button.sizeHint().width(),
                self.submit_code_button.sizeHint().width(),
                self.search_song_button.sizeHint().width(),
                self.schedule_button.sizeHint().width(),
            ]
        )
        margins = self.root_layout.contentsMargins()
        hint_width = max(
            content_width + margins.left() + margins.right(),
            min_button_width + margins.left() + margins.right() + 24,
        )
        hint_height = (
            self.header.sizeHint().height()
            + stack_height
            + self.status_label.sizeHint().height()
            + self.footer.sizeHint().height()
            + self.root_layout.spacing() * 3
            + self.root_layout.contentsMargins().top()
            + self.root_layout.contentsMargins().bottom()
        )
        desired_height = hint_height
        desired_width = max(target_size.width(), hint_width)

        screen = QtWidgets.QApplication.primaryScreen()
        if screen is not None and not self.isFullScreen():
            available = screen.availableGeometry()
            max_width = max(500, int(available.width() * 0.9))
            max_height = max(400, int(available.height() * 0.8))
            desired_width = min(desired_width, max_width)
            desired_height = min(desired_height, max_height)
            self.setMaximumSize(max_width, max_height)
        else:
            self.setMaximumSize(
                QtWidgets.QWIDGETSIZE_MAX, QtWidgets.QWIDGETSIZE_MAX
            )

        self.resize(desired_width, desired_height)

    def open_spotify_dashboard(self) -> None:
        webbrowser.open(SPOTIFY_DASHBOARD_URL)

    def open_song_search(self) -> None:
        if self.client is None:
            self._show_message(
                "Not authenticated",
                "Authenticate with Spotify first, then open the search.",
            )
            return

        dialog = SongSearchDialog(self, self.client)
        if dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return

        track = dialog.selected_track
        if not track or not track.get("uri"):
            self._show_message("No selection", "Select a track first.")
            return

        time_dialog = TimeInputDialog(self)
        if time_dialog.exec() != QtWidgets.QDialog.DialogCode.Accepted:
            return
        hour, minute, second = time_dialog.time_values()

        title = track.get("title", "Unknown track")
        artists = track.get("artists", "")
        label = f"{artists} - {title}" if artists else title
        try:
            self.append_song_to_songs_file(label, track["uri"], hour, minute, second)
        except Exception as exc:
            self._show_message("Add failed", str(exc))
            return

        self._show_message(
            "Song added",
            f"Added to songs.py at {hour:02d}:{minute:02d}:{second:02d}.",
        )
        if self.stack.currentWidget() == self.selection_page:
            self.load_track_metadata()

    def append_song_to_songs_file(
        self, label: str, uri: str, hour: int, minute: int, second: int
    ) -> None:
        path = ROOT_DIR / "songs.py"
        text = path.read_text(encoding="utf-8")

        start = text.find("SONG_SCHEDULES")
        if start == -1:
            raise RuntimeError("SONG_SCHEDULES not found in songs.py")
        bracket_start = text.find("[", start)
        if bracket_start == -1:
            raise RuntimeError("Song list bracket not found in songs.py")

        depth = 0
        end_index = None
        for idx in range(bracket_start, len(text)):
            char = text[idx]
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    end_index = idx
                    break

        if end_index is None:
            raise RuntimeError("Song list end not found in songs.py")

        safe_label = label.replace("\\", "\\\\").replace("\"", "\\\"")
        safe_uri = uri.replace("\\", "\\\\").replace("\"", "\\\"")

        entry = (
            "    SongSchedule(\n"
            f"        label=\"{safe_label}\",\n"
            f"        uri=\"{safe_uri}\",\n"
            f"        hour={hour},\n"
            f"        minute={minute},\n"
            f"        second={second},\n"
            "    ),\n"
        )

        insert_at = end_index
        new_text = text[:insert_at] + entry + text[insert_at:]
        path.write_text(new_text, encoding="utf-8")

    def generate_tls_cert(self) -> None:
        cert_path = resolve_path(self.cert_path_input.text(), DEFAULT_CERT_PATH)
        key_path = resolve_path(self.key_path_input.text(), DEFAULT_KEY_PATH)
        try:
            ensure_tls_cert_files(cert_path, key_path)
            self.cert_path_input.setText(str(cert_path))
            self.key_path_input.setText(str(key_path))
            self._set_status("TLS cert generated.")
            self._show_message("TLS cert generated", "Local HTTPS certificate is ready.")
        except Exception as exc:  # pragma: no cover - UI thread surface
            self._set_status(f"TLS cert error: {exc}")
            self._show_message("TLS cert error", str(exc))

    def start_callback_server(self) -> None:
        if not self.config.spotify_redirect_uri:
            raise ValueError("Redirect URI is required before login.")

        scheme, host, port, path = parse_redirect_uri(self.config.spotify_redirect_uri)
        cert_path = self.config.spotify_cert_path
        key_path = self.config.spotify_key_path

        if scheme == "https":
            ensure_tls_cert_files(cert_path, key_path)

        self.stop_callback_server()
        self.callback_thread = CallbackServerThread(
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            cert_path=cert_path,
            key_path=key_path,
        )
        self.callback_thread.status.connect(self._set_status)
        self.callback_thread.code_received.connect(self.on_callback_code)
        self.callback_thread.error_received.connect(self.on_callback_error)
        self.callback_thread.start()

    def stop_callback_server(self) -> None:
        if self.callback_thread and self.callback_thread.isRunning():
            self.callback_thread.stop()
            self.callback_thread.wait(2000)
        self.callback_thread = None

    def on_callback_code(self, code: str) -> None:
        self.code_input.setText(code)
        self._set_status("Auth code received from local callback.")
        self.submit_auth_code()

    def on_callback_error(self, message: str) -> None:
        self._set_status(f"Callback server error: {message}")
        self._show_message("Callback server error", message)

    def _selected_schedule(self) -> SongSchedule | None:
        item = self.song_list.currentItem()
        if item is None:
            return None
        return item.data(QtCore.Qt.ItemDataRole.UserRole)

    def _compute_target(self, schedule: SongSchedule) -> datetime:
        if self.config.spotify_test_mode and schedule.label == TEST_LABEL:
            return datetime.now() + timedelta(seconds=TEST_PLAY_DELAY_SECONDS)
        return schedule.target_datetime()

    def update_countdown(self) -> None:
        if not self.active_target:
            self.countdown_label.setText("Countdown: --:--:--")
            if self.countdown_timer.isActive():
                self.countdown_timer.stop()
            return

        remaining = self.active_target - datetime.now()
        total_seconds = int(max(0, remaining.total_seconds()))
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        seconds = total_seconds % 60
        self.countdown_label.setText(
            f"Countdown: {hours:02d}:{minutes:02d}:{seconds:02d}"
        )
        if total_seconds == 0 and self.countdown_timer.isActive():
            self.countdown_timer.stop()

    def _build_config_from_inputs(self) -> AppConfig:
        client_id = clean_value(self.client_id_input.text())
        client_secret = clean_value(self.client_secret_input.text())
        redirect_uri = clean_value(self.redirect_uri_input.text())

        cache_path = resolve_path(self.cache_path_input.text(), Path(".spotify_cache"))
        cert_path = resolve_path(self.cert_path_input.text(), DEFAULT_CERT_PATH)
        key_path = resolve_path(self.key_path_input.text(), DEFAULT_KEY_PATH)

        debug = self.debug_checkbox.isChecked()
        test_mode = self.test_mode_checkbox.isChecked()
        auth_code = clean_value(self.code_input.text()) or self.config.spotify_auth_code

        return AppConfig(
            debug=debug,
            spotify_client_id=client_id,
            spotify_client_secret=client_secret,
            spotify_redirect_uri=redirect_uri,
            spotify_cache_path=cache_path,
            spotify_auth_code=auth_code,
            spotify_cert_path=cert_path,
            spotify_key_path=key_path,
            spotify_test_mode=test_mode,
        )

    def save_settings(self) -> None:
        self.config = self._build_config_from_inputs()
        save_env_value("SPOTIFY_CLIENT_ID", self.client_id_input.text().strip())
        save_env_value("SPOTIFY_CLIENT_SECRET", self.client_secret_input.text().strip())
        save_env_value("SPOTIFY_REDIRECT_URI", self.redirect_uri_input.text().strip())
        cache_path_value = self.cache_path_input.text().strip() or ".spotify_cache"
        save_env_value("SPOTIFY_CACHE_PATH", cache_path_value)
        cert_path_value = self.cert_path_input.text().strip() or str(DEFAULT_CERT_PATH)
        key_path_value = self.key_path_input.text().strip() or str(DEFAULT_KEY_PATH)
        save_env_value("SPOTIFY_CERT_PATH", cert_path_value)
        save_env_value("SPOTIFY_KEY_PATH", key_path_value)
        save_env_value("DEBUG_MODE", "true" if self.debug_checkbox.isChecked() else "false")
        save_env_value(
            "SPOTIFY_TEST_MODE",
            "true" if self.test_mode_checkbox.isChecked() else "false",
        )
        if self.config.spotify_auth_code:
            save_env_value("SPOTIFY_AUTH_CODE", self.config.spotify_auth_code)
        self._set_status("Settings saved to .env")

    def open_login_page(self) -> None:
        try:
            self.save_settings()
            self.start_callback_server()
            self.auth_manager = create_auth_manager(self.config)
            login_url = self.auth_manager.get_authorize_url()
            self.login_url_label.setText(f"Login URL: {login_url}")
            self.code_input.setEnabled(True)
            self.submit_code_button.setEnabled(True)
            self._set_status("Login page opened. Waiting for callback.")
            webbrowser.open(login_url)
        except Exception as exc:  # pragma: no cover - UI thread surface
            self._set_status(f"Login error: {exc}")
            self._show_message("Login error", str(exc))

    def submit_auth_code(self) -> None:
        if self.auth_manager is None:
            self._set_status("Open the login page first.")
            return
        if self.exchange_thread and self.exchange_thread.isRunning():
            return
        try:
            code = extract_auth_code(self.code_input.text())
        except ValueError as exc:
            self._show_message("Invalid code", str(exc))
            return

        save_env_value("SPOTIFY_AUTH_CODE", code)
        self._set_status("Saved auth code to .env. Exchanging token...")

        self.submit_code_button.setEnabled(False)
        self.exchange_thread = CodeExchangeThread(self.auth_manager, code)
        self.exchange_thread.status.connect(self._set_status)
        self.exchange_thread.failure.connect(self.on_auth_failure)
        self.exchange_thread.success.connect(self.on_auth_success)
        self.exchange_thread.start()

    def on_auth_success(self, client) -> None:
        self.client = client
        self.submit_code_button.setEnabled(True)
        if self.search_song_button is not None:
            self.search_song_button.setEnabled(True)
        self.stack.setCurrentWidget(self.selection_page)
        self._set_status("Authenticated. Loading songs...")
        self.bring_to_front()
        self.stop_callback_server()
        self.load_track_metadata()

    def on_auth_failure(self, message: str) -> None:
        self.submit_code_button.setEnabled(True)
        self._set_status(f"Auth failed: {message}")
        self._show_message("Auth failed", message)

    def on_song_selected(self) -> None:
        item = self.song_list.currentItem()
        if item is None:
            self.selection_label.setText("Selected: none")
            return
        schedule = item.data(QtCore.Qt.ItemDataRole.UserRole)
        info = item.data(QtCore.Qt.ItemDataRole.UserRole + 1) or {}
        title = info.get("title", "Unknown track")
        artists = info.get("artists", "Unknown artist")
        target = self._compute_target(schedule)
        time_label = info.get("time_label", schedule_time_label(schedule))
        self.selection_label.setText(
            f"Selected: {title} — {artists} @ {time_label}"
        )

    def start_schedule(self) -> None:
        if self.playback_thread and self.playback_thread.isRunning():
            self.playback_thread.requestInterruption()
            self.playback_thread.wait(2000)
            self._set_status("Previous schedule canceled.")
        schedule = self._selected_schedule()
        if schedule is None:
            self._show_message("No selection", "Select a song schedule first.")
            return
        if self.client is None:
            self._show_message("Not authenticated", "Authenticate with Spotify first.")
            return

        target = self._compute_target(schedule)
        if target <= datetime.now():
            self._show_message(
                "Time in the past",
                "Target time is in the past. Choose another schedule.",
            )
            return

        self.active_target = target
        self.active_schedule = schedule
        self.update_countdown()
        self.countdown_timer.start()

        self._set_status(f"Scheduled for {format_datetime(target)}")
        self.playback_thread = PlaybackThread(self.client, schedule, target)
        self.playback_thread.status.connect(self._set_status)
        self.playback_thread.failure.connect(self.on_playback_failure)
        self.playback_thread.finished_ok.connect(self.on_playback_done)
        self.playback_thread.start()

    def on_playback_failure(self, message: str) -> None:
        self._set_status(f"Playback failed: {message}")
        self._show_message("Playback failed", message)
        self.active_target = None
        self.active_schedule = None
        self.update_countdown()

    def on_playback_done(self) -> None:
        self._set_status("Playback command sent.")
        self.active_target = None
        self.active_schedule = None
        self.update_countdown()

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self.stop_callback_server()
        if self.playback_thread and self.playback_thread.isRunning():
            self.playback_thread.requestInterruption()
            self.playback_thread.wait(2000)
        super().closeEvent(event)


def main() -> int:
    app = QtWidgets.QApplication(sys.argv)
    icon_path = ROOT_DIR / "Spotify_logo_without_text.svg.png"
    app_icon = QtGui.QIcon(str(icon_path))
    app.setWindowIcon(app_icon)
    app.setFont(QtGui.QFont("Avenir Next", 11))
    app.setStyleSheet(
        """
        QWidget#root {
            background: #0b0b0b;
            color: #f5f5f5;
        }
        QWidget#header {
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #1a1a1a, stop:1 #0f1a14);
            border: 1px solid #262626;
            border-radius: 14px;
        }
        QLabel#appTitle {
            font-size: 18px;
            font-weight: 700;
            color: #ffffff;
        }
        QLabel#appSubtitle {
            font-size: 11px;
            color: #b3b3b3;
        }
        QWidget#footer {
            background: #111111;
            border: 1px solid #262626;
            border-radius: 12px;
        }
        QLabel#githubBadge {
            background: #1f1f1f;
            color: #1db954;
            border-radius: 11px;
            font-weight: 700;
            font-size: 10px;
        }
        QLabel#footerLink {
            font-size: 12px;
            color: #1db954;
        }
        QLabel#footerLink:hover {
            color: #6bff95;
        }
        QLabel#sectionTitle {
            font-size: 16px;
            font-weight: 600;
            color: #ffffff;
        }
        QLabel#countdown {
            padding: 12px 16px;
            border-radius: 14px;
            background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                stop:0 #1db954, stop:1 #6bff95);
            color: #0b0b0b;
        }
        QLabel#selectionLabel {
            color: #d9d9d9;
        }
        QGroupBox {
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            margin-top: 10px;
            padding: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 12px;
            padding: 0 6px;
            color: #c5c5c5;
        }
        QTabWidget::pane {
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            background: #121212;
        }
        QTabBar::tab {
            background: #1a1a1a;
            color: #c9c9c9;
            padding: 8px 14px;
            border-top-left-radius: 8px;
            border-top-right-radius: 8px;
            margin-right: 4px;
        }
        QTabBar::tab:selected {
            background: #232323;
            color: #ffffff;
        }
        QLineEdit, QListWidget {
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 10px;
            padding: 8px 10px;
            color: #f0f0f0;
        }
        QLineEdit:focus {
            border: 1px solid #1db954;
        }
        QListWidget::item {
            border: 1px solid transparent;
        }
        QListWidget::item:selected {
            background: #1f2a22;
            border: 1px solid #1db954;
            border-radius: 10px;
        }
        QLabel#songTitle {
            font-weight: 600;
            color: #ffffff;
        }
        QLabel#songMeta {
            color: #b3b3b3;
        }
        QPushButton {
            background: #1db954;
            color: #0b0b0b;
            border: none;
            border-radius: 18px;
            padding: 10px 18px;
            min-height: 36px;
            font-weight: 600;
        }
        QPushButton:disabled {
            background: #2a2a2a;
            color: #6f6f6f;
        }
        QPushButton:hover {
            background: #28d463;
        }
        """
    )

    config = load_config()
    window = MainWindow(config, app_icon)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
