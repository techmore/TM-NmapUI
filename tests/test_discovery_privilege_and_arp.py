"""Discovery must not silently miss live hosts.

Unprivileged `nmap -sn` only probes TCP 80/443, so on a typical office LAN it
misses printers, phones and IoT devices. Discovery therefore uses the scanner's
privilege prefix when available, and hosts that answer ARP are kept even when
they ignore Nmap's ping probes.
"""
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from nmapui.jobs import ClientJobRegistry
from nmapui.workflow_context import build_scan_workflow_context
from nmapui.workflows import merge_arp_only_hosts, start_scan_task

SWEEP = (
    "Nmap scan report for 192.168.50.10\nHost is up (0.001s latency).\n"
    "Nmap done: 256 IP addresses (1 host up) scanned in 3.00 seconds\n"
)


def _context(*, commands, deep_calls, events, results, arp_data, settings=None):
    registry = ClientJobRegistry()
    registry.start("sid", "scan")
    queue = list(results)

    def run(argv, **kwargs):
        commands.append(argv)
        return queue.pop(0) if queue else SimpleNamespace(stdout=SWEEP, stderr="", returncode=0)

    return build_scan_workflow_context({
        "get_client_state": lambda **kwargs: {},
        "settings_state": settings or {"scan_rules": {"firewall_discovery_only": False}},
        "ensure_job_not_cancelled": lambda *args: None,
        "idle_state_manager": SimpleNamespace(start_operation=lambda *a: None, end_operation=lambda *a: None),
        "update_job_progress": lambda *args, **kwargs: registry.update("sid", "scan", details=kwargs.get("details", {})),
        "emit_to_client": lambda sid, event, data=None: events.append((event, data)),
        "socketio_sleep": lambda *args: None,
        "run_cancellable_command": run,
        "run_arp_scan": lambda *args, **kwargs: arp_data,
        "identify_gateway_firewall_targets": lambda hosts: (hosts, []),
        "start_deep_scan": lambda ctx, targets, sid, **kwargs: deep_calls.append((list(targets), kwargs.get("skip_host_discovery", False))),
        "job_registry": registry,
        "emit_job_status": lambda *args: None,
        "logger": logging.getLogger("fixture"),
        "vulners_script": Path("unused"),
        "ip_sort_key": lambda ip: tuple(int(part) for part in ip.split(".")),
    })


def test_discovery_uses_privilege_prefix(monkeypatch):
    monkeypatch.setattr("nmapui.workflows.privileged.privileged_prefix", lambda: ["sudo", "-n", "/helper"])
    commands, deep, events = [], [], []
    start_scan_task(_context(commands=commands, deep_calls=deep, events=events, results=[], arp_data={}), "sid", "192.168.50.0/24")
    assert commands[0] == ["sudo", "-n", "/helper", "nmap", "-sn", "192.168.50.0/24"]
    assert deep == [(["192.168.50.10"], False)]


def test_discovery_falls_back_when_privilege_is_denied(monkeypatch):
    monkeypatch.setattr("nmapui.workflows.privileged.privileged_prefix", lambda: ["sudo", "-n"])
    denied = SimpleNamespace(stdout="", stderr="sudo: a password is required", returncode=1)
    commands, deep, events = [], [], []
    start_scan_task(_context(commands=commands, deep_calls=deep, events=events, results=[denied], arp_data={}), "sid", "192.168.50.0/24")
    assert commands[:2] == [["sudo", "-n", "nmap", "-sn", "192.168.50.0/24"], ["nmap", "-sn", "192.168.50.0/24"]]
    assert any("Privileged discovery denied" in str(data) for event, data in events if event == "scan_feedback")
    assert deep == [(["192.168.50.10"], False)]


def test_scan_only_mode_never_uses_privilege(monkeypatch):
    monkeypatch.setattr("nmapui.workflows.privileged.privileged_prefix", lambda: ["sudo", "-n"])
    commands, deep, events = [], [], []
    settings = {"scan_rules": {"scan_only_mode": True, "firewall_discovery_only": False}}
    start_scan_task(_context(commands=commands, deep_calls=deep, events=events, results=[], arp_data={}, settings=settings), "sid", "192.168.50.0/24")
    assert commands[0] == ["nmap", "-sn", "192.168.50.0/24"]


def test_arp_only_hosts_are_reported_and_service_scanned(monkeypatch):
    monkeypatch.setattr("nmapui.workflows.privileged.privileged_prefix", lambda: [])
    arp = {
        "192.168.50.10": {"mac": "aa:bb:cc:00:00:10", "vendor": "Known"},
        "192.168.50.20": {"mac": "aa:bb:cc:00:00:20", "vendor": "Printer Co"},
        "192.168.51.5": {"mac": "aa:bb:cc:00:00:05", "vendor": "Outside target"},
    }
    commands, deep, events = [], [], []
    start_scan_task(_context(commands=commands, deep_calls=deep, events=events, results=[], arp_data=arp), "sid", "192.168.50.0/24")
    results = next(data for event, data in events if event == "scan_results")
    assert [host["ip"] for host in results] == ["192.168.50.10", "192.168.50.20"]
    assert results[1]["vendor"] == "Printer Co" and results[1]["status"] == "up"
    # The ARP-only host is service-scanned with -Pn, the pinged host without.
    assert deep == [(["192.168.50.10"], False), (["192.168.50.20"], True)]
    assert any("ARP found 1 live host" in str(data) for event, data in events if event == "scan_feedback")


@pytest.mark.parametrize("target", ["192.168.50.1-40", "printer.local", ""])
def test_merge_ignores_non_cidr_targets(target):
    hosts = []
    assert merge_arp_only_hosts(hosts, {"192.168.50.20": {}}, target) == []
    assert hosts == []


def test_merge_skips_network_broadcast_and_invalid_addresses():
    hosts = [{"ip": "10.0.0.5"}]
    arp = {"10.0.0.0": {}, "10.0.0.255": {}, "10.0.0.5": {}, "not-an-ip": {}, "10.0.0.9": {}}
    added = merge_arp_only_hosts(hosts, arp, "10.0.0.0/24")
    assert [host["ip"] for host in added] == ["10.0.0.9"]
    assert added[0]["discovered_by"] == "arp"
