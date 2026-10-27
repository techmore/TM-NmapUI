import subprocess

from nmapui.traceroute import run_traceroute


def test_disabled_network_fingerprint_runs_no_probe_or_ip_lookup(monkeypatch):
    monkeypatch.setenv("NMAPUI_ENABLE_NETWORK_FINGERPRINT", "false")
    events = []
    persisted = []

    def unexpected_probe(*_args, **_kwargs):
        raise AssertionError("disabled network fingerprint attempted a probe")

    monkeypatch.setattr(subprocess, "check_output", unexpected_probe)
    state = {
        "network_key": {
            "target": "1.1.1.1",
            "hops": [],
            "private_hops": [],
            "public_hops": [],
            "total_hops": 0,
        },
        "current_customer": {},
    }
    result = run_traceroute(
        "1.1.1.1",
        sid="sid-test",
        deps={
            "emit_to_client": lambda _sid, event, data=None: events.append((event, data)),
            "safe_emit": lambda event, data=None: events.append((event, data)),
            "get_client_state": lambda sid=None: state,
            "socketio_sleep": lambda _seconds: None,
            "logger": __import__("logging").getLogger("test"),
            "is_private_ip": lambda _ip: False,
            "requests": None,
            "set_network_key_state": lambda *, value, sid=None: persisted.append((sid, value)),
            "get_customer_fingerprinter": lambda: None,
            "merge_customer_metadata": lambda **_kwargs: None,
            "set_current_customer_state": lambda **_kwargs: None,
            "get_current_customer_state": lambda **_kwargs: {},
        },
    )

    assert result["error"] == "Network fingerprinting disabled by configuration"
    assert persisted[0][0] == "sid-test"
    assert any(event == "network_key" for event, _data in events)
