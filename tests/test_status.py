"""StatusTracker, the logging handler, the loopback server, and agent wiring."""

import json
import logging
import urllib.error
import urllib.request
from urllib.parse import urljoin

import pytest

from security_agent import agent as agent_mod
from security_agent.agent import Agent, main
from security_agent.status import (
    StatusLogHandler,
    StatusServer,
    StatusTracker,
)
from tests._helpers import fake_resolver, make_config

VALID_YAML = """\
engagement: {name: cli, authorized_by: Owner, authorization_ref: T-1}
scope: {domains: [staging.example.com]}
reporting: {evidence_dir: "%s", allow_unscanned_report: true}
"""

PHASES = ["discovery", "infrastructure", "webapp", "automation", "reporting"]


def test_tracker_lifecycle_and_snapshot_isolation():
    t = StatusTracker("eng", PHASES)
    snap = t.snapshot()
    assert snap["overall"] == "pending"
    assert [p["name"] for p in snap["phases"]] == PHASES
    assert all(p["state"] == "pending" for p in snap["phases"])

    # Mutating the snapshot must not leak into the tracker.
    snap["phases"][0]["state"] = "tampered"
    snap["events"].append({"x": "y"})
    assert t.snapshot()["phases"][0]["state"] == "pending"
    assert t.snapshot()["events"] == []

    t.start()
    t.set_phase("discovery", "completed")
    t.add_findings(3)
    t.finish("completed")
    snap = t.snapshot()
    assert snap["overall"] == "completed"
    assert snap["started_at"] is not None
    assert snap["findings"] == 3
    assert snap["phases"][0]["state"] == "completed"


def test_tracker_rejects_bad_states():
    t = StatusTracker("eng", PHASES)
    with pytest.raises(ValueError):
        t.set_phase("discovery", "nonsense")
    with pytest.raises(ValueError):
        t.finish("nonsense")


def test_tracker_ignores_unknown_phase():
    t = StatusTracker("eng", PHASES)
    t.set_phase("not-a-phase", "running")  # no error, no new phase
    assert [p["name"] for p in t.snapshot()["phases"]] == PHASES


def test_event_ring_buffer_bounded():
    t = StatusTracker("eng", PHASES, max_events=5)
    for i in range(20):
        t.event("INFO", f"line {i}")
    events = t.snapshot()["events"]
    assert len(events) == 5
    assert events[0]["message"] == "line 15"
    assert events[-1]["message"] == "line 19"


def test_events_are_tagged_with_running_phase():
    t = StatusTracker("eng", PHASES)
    t.start()
    t.event("INFO", "before any phase")      # no phase running yet
    t.set_phase("discovery", "running")
    t.event("INFO", "discovery: scanning")
    t.set_phase("discovery", "completed")
    t.set_phase("webapp", "running")
    t.event("INFO", "webapp: probing")
    evs = t.snapshot()["events"]
    assert evs[0]["phase"] is None
    assert evs[1]["phase"] == "discovery"
    assert evs[2]["phase"] == "webapp"       # stays with the latest running phase


def test_log_handler_feeds_tracker():
    t = StatusTracker("eng", PHASES)
    logger = logging.getLogger("status-test")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.addHandler(StatusLogHandler(t))
    logger.info("discovery: running nmap against %s", "10.0.5.1")
    events = t.snapshot()["events"]
    assert events[-1]["level"] == "INFO"
    assert events[-1]["message"] == "discovery: running nmap against 10.0.5.1"


# Talk to the loopback server directly, never through a system/env HTTP proxy
# (a proxy would send absolute-form requests and the server would 404).
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class _ServerFixture:
    def __init__(self, tracker):
        self.server = StatusServer(tracker, port=0)  # ephemeral port
        self.url = self.server.start()

    def get(self, path):
        # urljoin resolves `path` (no leading slash) against the base URL,
        # so "status.json" -> ".../status.json" and "" -> ".../".
        with _DIRECT.open(urljoin(self.url, path)) as resp:  # noqa: S310 - loopback
            return resp.status, resp.headers.get("Content-Type"), resp.read()


def test_server_serves_status_json_and_page():
    t = StatusTracker("my-engagement", PHASES)
    t.start()
    t.event("INFO", "hello")
    fx = _ServerFixture(t)
    try:
        status, ctype, body = fx.get("status.json")
        assert status == 200
        assert "application/json" in ctype
        data = json.loads(body)
        assert data["engagement"] == "my-engagement"
        assert data["overall"] == "running"
        assert data["events"][-1]["message"] == "hello"

        status, ctype, body = fx.get("")
        assert status == 200
        assert "text/html" in ctype
        assert b"Security agent" in body

        status, _, _ = fx.get("nope")
        assert status == 404
    finally:
        fx.server.stop()


def test_server_stop_is_idempotent():
    server = StatusServer(StatusTracker("e", PHASES), port=0)
    server.start()
    server.stop()
    server.stop()  # must not raise
    assert server.url is None


def test_agent_run_drives_tracker(tmp_path, monkeypatch):
    # No human at the terminal: discovery is denied but completes (no findings);
    # the three stub phases are skipped; reporting completes.
    monkeypatch.setattr("sys.stdin", None)
    agent = Agent(make_config(tmp_path), resolver=fake_resolver())
    tracker = StatusTracker(agent.config.name, agent.phase_names)
    agent.enable_status(tracker)
    agent.run()

    snap = tracker.snapshot()
    states = {p["name"]: p["state"] for p in snap["phases"]}
    assert snap["overall"] == "completed"
    assert states["discovery"] == "completed"
    assert states["infrastructure"] == "skipped"
    assert states["webapp"] == "skipped"
    assert states["automation"] == "skipped"
    assert states["reporting"] == "completed"
    # The log feed captured activity from the run.
    assert snap["events"]


def test_agent_run_marks_failed_phase_and_aborts(tmp_path):
    agent = Agent(make_config(tmp_path), resolver=fake_resolver())
    tracker = StatusTracker(agent.config.name, agent.phase_names)
    agent.enable_status(tracker)

    def boom(_targets):
        raise RuntimeError("kaboom")

    agent.components[0].run = boom
    with pytest.raises(RuntimeError):
        agent.run()

    snap = tracker.snapshot()
    states = {p["name"]: p["state"] for p in snap["phases"]}
    assert snap["overall"] == "aborted"
    assert states["discovery"] == "failed"
    # Reporting still ran in the finally block.
    assert states["reporting"] == "completed"


def test_cli_status_web_runs_and_serves(tmp_path, monkeypatch, capsys):
    # Exercise the whole --status-web path: build the server, run, and the
    # post-run keep-alive. (A missing import here would NameError before this.)
    monkeypatch.setattr(
        agent_mod.ScopeGuard, "resolution_problems", lambda self, resolver: ([], [])
    )
    monkeypatch.setattr("sys.stdin", None)  # no human: discovery denied but completes

    # The CLI blocks after the run so the page stays viewable; replace that with
    # an immediate stop so the test does not hang.
    monkeypatch.setattr(agent_mod, "_serve_until_interrupt", lambda server: server.stop())

    path = tmp_path / "e.yaml"
    path.write_text(VALID_YAML % (tmp_path / "ev"))
    rc = main(["--config", str(path), "--status-web", "--status-port", "0"])
    assert rc == 0
    assert "Live status page: http://127.0.0.1:" in capsys.readouterr().out
