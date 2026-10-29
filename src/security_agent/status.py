"""Live run-status web page.

An optional, read-only dashboard for watching an engagement as it runs. A
``StatusTracker`` is the single source of truth: the agent updates phase state
on it, and a logging handler feeds it the same audit stream the console and
``audit.log`` receive. Because the agent attaches its redaction filter at the
logger level, the feed the page shows is redacted exactly like the audit log.

A small stdlib HTTP server exposes the state as JSON and serves one
self-contained HTML page that polls it. The server:

* binds to loopback only (``127.0.0.1`` by default),
* is strictly read-only -- it accepts no input and has no side effects, and
* exposes nothing beyond phase state, a findings count, and the redacted log
  feed (never raw evidence, requests, or responses).

It adds no third-party dependencies; everything here is from the standard
library. The page escapes all dynamic text as plain text, so a log line can
never inject markup into the dashboard.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

#: Per-phase lifecycle states, in the order a phase moves through them.
PHASE_STATES = ("pending", "running", "completed", "skipped", "failed")
#: Overall run states.
OVERALL_STATES = ("pending", "running", "completed", "aborted")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class StatusTracker:
    """Thread-safe record of a run's progress.

    The agent (main thread) writes to it; the HTTP server (its own thread)
    reads ``snapshot()``. Every method takes the lock, and ``snapshot`` returns
    freshly built containers so callers cannot mutate internal state.
    """

    def __init__(self, engagement: str, phases: list[str], *, max_events: int = 300) -> None:
        self._lock = threading.Lock()
        self._engagement = engagement
        self._order = list(phases)
        self._phases = {name: "pending" for name in phases}
        self._overall = "pending"
        self._started_at: str | None = None
        self._updated_at = _now_iso()
        self._findings = 0
        # The phase currently running, so events can be attributed to it.
        self._current_phase: str | None = None
        self._events: deque[dict[str, str | None]] = deque(maxlen=max_events)

    def start(self) -> None:
        with self._lock:
            self._overall = "running"
            self._started_at = self._updated_at = _now_iso()

    def set_phase(self, name: str, state: str) -> None:
        if state not in PHASE_STATES:
            raise ValueError(f"phase state must be one of {PHASE_STATES}, got {state!r}")
        with self._lock:
            if name in self._phases:
                self._phases[name] = state
                if state == "running":
                    self._current_phase = name
            self._updated_at = _now_iso()

    def add_findings(self, count: int) -> None:
        with self._lock:
            self._findings += count
            self._updated_at = _now_iso()

    def finish(self, overall: str) -> None:
        if overall not in OVERALL_STATES:
            raise ValueError(f"overall state must be one of {OVERALL_STATES}, got {overall!r}")
        with self._lock:
            self._overall = overall
            self._updated_at = _now_iso()

    def event(self, level: str, message: str) -> None:
        with self._lock:
            self._events.append({
                "time": _now_iso(),
                "level": level,
                "message": message,
                "phase": self._current_phase,
            })
            self._updated_at = _now_iso()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "engagement": self._engagement,
                "overall": self._overall,
                "started_at": self._started_at,
                "updated_at": self._updated_at,
                "findings": self._findings,
                "phases": [{"name": n, "state": self._phases[n]} for n in self._order],
                "events": list(self._events),
            }


class StatusLogHandler(logging.Handler):
    """Logging handler that mirrors each record into a ``StatusTracker``.

    Attach it to the agent logger *after* any redaction filter, so the message
    it stores is already scrubbed. It never raises into the logging machinery.
    """

    def __init__(self, tracker: StatusTracker) -> None:
        super().__init__()
        self._tracker = tracker

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._tracker.event(record.levelname, record.getMessage())
        except Exception:  # noqa: BLE001 - logging must never crash the run
            self.handleError(record)


def _make_handler(tracker: StatusTracker) -> type[BaseHTTPRequestHandler]:
    class _StatusHandler(BaseHTTPRequestHandler):
        # Serve only GET; the dashboard is read-only.
        def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
            path = self.path.split("?", 1)[0]
            if path == "/status.json":
                self._respond(200, "application/json; charset=utf-8",
                              json.dumps(tracker.snapshot()).encode("utf-8"))
            elif path in ("/", "/index.html"):
                self._respond(200, "text/html; charset=utf-8", _PAGE)
            else:
                self._respond(404, "text/plain; charset=utf-8", b"not found")

        def _respond(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: Any) -> None:
            # Silence the default stderr access log; the audit log is the record.
            return

    return _StatusHandler


class StatusServer:
    """Serve a ``StatusTracker`` on loopback in a background daemon thread."""

    def __init__(self, tracker: StatusTracker, *, host: str = "127.0.0.1", port: int = 8765) -> None:
        self._tracker = tracker
        self._host = host
        self._port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str | None:
        if self._httpd is None:
            return None
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/"

    def start(self) -> str:
        self._httpd = ThreadingHTTPServer((self._host, self._port), _make_handler(self._tracker))
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="status-server", daemon=True
        )
        self._thread.start()
        url = self.url
        if url is None:  # pragma: no cover - set by start() above
            raise RuntimeError("status server failed to bind")
        return url

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


# A single self-contained page: no external scripts, fonts, or styles. It polls
# /status.json once a second and renders the tracker. All dynamic values are set
# via textContent, so log text is shown literally and can never inject markup.
_PAGE = b"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security agent - run status</title>
<style>
  :root {
    --bg: #0f1419; --panel: #1a2029; --border: #2b3440; --text: #e6edf3;
    --muted: #8b949e; --accent: #58a6ff;
    --pending: #6e7681; --running: #d29922; --completed: #3fb950;
    --skipped: #8b949e; --failed: #f85149; --aborted: #f85149;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  header {
    padding: 20px 24px; border-bottom: 1px solid var(--border);
    display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px 16px;
  }
  header h1 { font-size: 18px; margin: 0; font-weight: 600; }
  header .eng { color: var(--accent); }
  header .meta { color: var(--muted); font-size: 13px; }
  .pill {
    font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em;
    padding: 3px 10px; border-radius: 999px; color: #0f1419;
  }
  main { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
  h2 {
    font-size: 13px; text-transform: uppercase; letter-spacing: .06em;
    color: var(--muted); margin: 24px 0 10px;
  }
  .stat { color: var(--muted); font-size: 13px; margin: 0 0 12px; }
  .phases { display: grid; gap: 8px; }
  .phase {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; overflow: hidden;
  }
  .phase > summary {
    list-style: none; cursor: pointer; user-select: none;
    display: flex; align-items: center; gap: 12px; padding: 12px 14px;
  }
  .phase > summary::-webkit-details-marker { display: none; }
  .chev { color: var(--muted); flex: none; font-size: 10px; transition: transform .15s; }
  .phase[open] .chev { transform: rotate(90deg); }
  .dot { width: 10px; height: 10px; border-radius: 50%; flex: none; }
  .phase .name { flex: 1; font-weight: 500; text-transform: capitalize; }
  .count { color: var(--muted); font-size: 12px; }
  .badge { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; }
  .events {
    border-top: 1px solid var(--border); background: #0b0e13;
    padding: 8px 14px; max-height: 260px; overflow-y: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px;
  }
  .events .line { display: flex; gap: 10px; padding: 2px 0; white-space: pre-wrap; word-break: break-word; }
  .events .t { color: var(--muted); flex: none; }
  .events .lvl { flex: none; width: 56px; font-weight: 600; }
  .events .INFO { color: var(--accent); } .events .WARNING { color: var(--running); }
  .events .ERROR, .events .CRITICAL { color: var(--failed); } .events .DEBUG { color: var(--muted); }
  .empty { color: var(--muted); font-style: italic; padding: 2px 0; }
  footer { text-align: center; color: var(--muted); font-size: 12px; padding: 16px; }
  .offline { color: var(--failed); }
</style>
</head>
<body>
<header>
  <h1>Security agent &middot; <span class="eng" id="engagement">...</span></h1>
  <span class="pill" id="overall">pending</span>
  <span class="meta" id="meta"></span>
</header>
<main>
  <h2>Phases</h2>
  <p class="stat" id="findings"></p>
  <div class="phases" id="phases"></div>
  <div id="other"></div>
</main>
<footer id="footer">Live view &middot; refreshing every second</footer>
<script>
"use strict";
var STATE_COLORS = {
  pending: "--pending", running: "--running", completed: "--completed",
  skipped: "--skipped", failed: "--failed", aborted: "--aborted"
};
// Remember which panels the viewer expanded/collapsed, so a 1s refresh does
// not fight their clicks. Undefined => use the default (running = open).
var openState = {};
function color(state) {
  var v = getComputedStyle(document.documentElement).getPropertyValue(STATE_COLORS[state] || "--pending");
  return v.trim() || "#6e7681";
}
function eventsPanel(events) {
  var box = document.createElement("div"); box.className = "events";
  if (!events.length) {
    var e = document.createElement("div"); e.className = "empty";
    e.textContent = "No activity yet."; box.appendChild(e); return box;
  }
  events.forEach(function (ev) {
    var line = document.createElement("div"); line.className = "line";
    var t = document.createElement("span"); t.className = "t"; t.textContent = ev.time;
    var lvl = document.createElement("span"); lvl.className = "lvl " + ev.level; lvl.textContent = ev.level;
    var msg = document.createElement("span"); msg.textContent = ev.message;
    line.appendChild(t); line.appendChild(lvl); line.appendChild(msg); box.appendChild(line);
  });
  return box;
}
function phasePanel(key, label, stateName, events, defaultOpen) {
  var det = document.createElement("details"); det.className = "phase";
  det.open = (key in openState) ? openState[key] : defaultOpen;
  det.addEventListener("toggle", function () { openState[key] = det.open; });
  var sum = document.createElement("summary");
  var chev = document.createElement("span"); chev.className = "chev"; chev.textContent = "\\u25B6";
  sum.appendChild(chev);
  if (stateName) {
    var dot = document.createElement("span"); dot.className = "dot";
    dot.style.background = color(stateName); sum.appendChild(dot);
  }
  var name = document.createElement("span"); name.className = "name"; name.textContent = label;
  sum.appendChild(name);
  var count = document.createElement("span"); count.className = "count";
  count.textContent = events.length ? (events.length + (events.length === 1 ? " event" : " events")) : "";
  sum.appendChild(count);
  if (stateName) {
    var badge = document.createElement("span"); badge.className = "badge";
    badge.style.color = color(stateName); badge.textContent = stateName; sum.appendChild(badge);
  }
  det.appendChild(sum);
  var panel = eventsPanel(events); det.appendChild(panel);
  // Keep the live phase scrolled to its newest line.
  if (stateName === "running" && det.open) panel.scrollTop = panel.scrollHeight;
  return det;
}
function render(s) {
  document.getElementById("engagement").textContent = s.engagement || "(unnamed)";
  var overall = document.getElementById("overall");
  overall.textContent = s.overall;
  overall.style.background = color(s.overall);
  var meta = [];
  if (s.started_at) meta.push("started " + s.started_at);
  if (s.updated_at) meta.push("updated " + s.updated_at);
  document.getElementById("meta").textContent = meta.join("  \\u00b7  ");
  document.getElementById("findings").textContent =
    s.findings === 1 ? "1 finding so far" : s.findings + " findings so far";

  var byPhase = {}, other = [];
  (s.events || []).forEach(function (ev) {
    if (ev.phase) { (byPhase[ev.phase] = byPhase[ev.phase] || []).push(ev); }
    else { other.push(ev); }
  });

  var phases = document.getElementById("phases");
  phases.textContent = "";
  (s.phases || []).forEach(function (p) {
    var evs = byPhase[p.name] || [];
    phases.appendChild(phasePanel(p.name, p.name, p.state, evs, p.state === "running"));
  });

  var otherWrap = document.getElementById("other");
  otherWrap.textContent = "";
  if (other.length) {
    otherWrap.appendChild(phasePanel("__other", "Other activity", null, other, false));
  }
}
function poll() {
  fetch("status.json", { cache: "no-store" })
    .then(function (r) { return r.json(); })
    .then(function (s) {
      render(s);
      document.getElementById("footer").textContent = "Live view \\u00b7 refreshing every second";
      document.getElementById("footer").className = "";
    })
    .catch(function () {
      var f = document.getElementById("footer");
      f.textContent = "Lost connection to the agent (the run may have ended).";
      f.className = "offline";
    });
}
poll();
setInterval(poll, 1000);
</script>
</body>
</html>
"""
