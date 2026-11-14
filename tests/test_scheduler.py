"""Scheduler picks due, enabled feeds and runs them one by one."""
from threatintel import collectors, scheduler


def test_tick_runs_due_feeds(conn, monkeypatch):
    for name in collectors.REGISTRY:
        collectors.set_enabled(conn, name, name == "feodo")
    calls = []
    monkeypatch.setattr(collectors, "run_feed", lambda name, **kw: calls.append(name) or {"status": "skipped", "rows": 0})
    s = scheduler.Scheduler()
    s.enabled = True
    s.correlate_after = False
    assert s.due_feeds(conn) == ["feodo"]
    assert s.tick() == [{"feed": "feodo", "status": "skipped", "rows": 0}]
    assert calls == ["feodo"]
    for name in collectors.REGISTRY:
        collectors.set_enabled(conn, name, None)
