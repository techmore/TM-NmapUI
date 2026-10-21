"""Static accessibility contract for the main dashboard template.

These checks run without a browser. They pin the markup the keyboard, screen
reader and dark-mode fixes depend on so a later template edit cannot quietly
undo them.
"""

import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "templates" / "index.html"
STATIC_JS = ROOT / "static" / "js"


class _ElementCollector(HTMLParser):
    """Collects (tag, attrs) tuples; enough for attribute-level assertions."""

    def __init__(self):
        super().__init__()
        self.elements = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


def _elements():
    collector = _ElementCollector()
    collector.feed(TEMPLATE.read_text(encoding="utf-8"))
    return collector.elements


def _by_id(elements, element_id):
    for tag, attrs in elements:
        if attrs.get("id") == element_id:
            return tag, attrs
    raise AssertionError(f"#{element_id} is missing from templates/index.html")


def test_document_declares_language_and_charset():
    template = TEMPLATE.read_text(encoding="utf-8")
    assert '<html lang="en">' in template
    assert '<meta charset="utf-8" />' in template


def test_every_image_has_alternative_text():
    for tag, attrs in _elements():
        if tag == "img":
            assert "alt" in attrs, f"<img src={attrs.get('src')!r}> needs an alt attribute"


def test_tab_strip_uses_aria_tabs_pattern():
    elements = _elements()
    tablists = [attrs for tag, attrs in elements if attrs.get("role") == "tablist"]
    assert len(tablists) == 1

    tabs = [attrs for tag, attrs in elements if attrs.get("role") == "tab"]
    assert [tab["id"] for tab in tabs] == [
        "tab-dashboard-btn",
        "tab-history-btn",
        "tab-reports-btn",
        "tab-customers-btn",
        "tab-logs-btn",
        "tab-settings-btn",
    ]
    for tab in tabs:
        panel_tag, panel_attrs = _by_id(elements, tab["aria-controls"])
        assert panel_attrs.get("role") == "tabpanel"
        assert panel_attrs.get("aria-labelledby") == tab["id"]
        assert tab.get("aria-selected") in {"true", "false"}

    # Exactly one tab is in the Tab order (roving tabindex).
    selected = [tab for tab in tabs if tab["aria-selected"] == "true"]
    assert len(selected) == 1 and "tabindex" not in selected[0]
    assert all(tab.get("tabindex") == "-1" for tab in tabs if tab["aria-selected"] == "false")


def test_every_modal_is_a_labelled_dialog():
    elements = _elements()
    ids = {attrs.get("id") for _, attrs in elements if attrs.get("id")}
    overlays = [attrs for _, attrs in elements if "modal-overlay" in (attrs.get("class") or "").split()]
    assert len(overlays) >= 6
    for overlay in overlays:
        assert overlay.get("role") == "dialog", overlay.get("id")
        assert overlay.get("aria-modal") == "true", overlay.get("id")
        assert overlay.get("aria-labelledby") in ids, overlay.get("id")


def test_modal_keyboard_support_is_loaded_after_action_delegation():
    template = TEMPLATE.read_text(encoding="utf-8")
    actions_index = template.index('src="/static/js/template_actions.js"')
    a11y_index = template.index('src="/static/js/modal_a11y.js"')
    assert actions_index < a11y_index
    script = (STATIC_JS / "modal_a11y.js").read_text(encoding="utf-8")
    assert "'Escape'" in script
    assert "'Tab'" in script
    assert "MutationObserver" in script


def test_form_fields_in_dialogs_have_explicit_labels():
    elements = _elements()
    label_targets = {attrs.get("for") for tag, attrs in elements if tag == "label" and attrs.get("for")}
    for field_id in (
        "cust-name",
        "cust-id",
        "cust-description",
        "cust-location",
        "cust-connection-type",
        "cust-public-ip",
        "cust-gateway",
        "cust-exit-pattern",
        "cust-hop-count",
        "cust-private-ranges",
        "auto-start-time",
        "auto-end-time",
    ):
        assert field_id in label_targets, f"#{field_id} has no <label for>"
    for field_id in ("history-customer-filter", "history-date-filter", "scan-target", "customer-quick-add"):
        _, attrs = _by_id(elements, field_id)
        assert attrs.get("aria-label") or field_id in label_targets, field_id


def test_scan_status_regions_are_live():
    elements = _elements()
    _, report_status = _by_id(elements, "report-status")
    assert report_status.get("aria-live") == "polite"
    assert report_status.get("role") == "status"
    for status_id in ("history-tab-status", "reports-tab-status", "customers-tab-status", "settings-tab-status"):
        _, attrs = _by_id(elements, status_id)
        assert attrs.get("aria-live") == "polite", status_id

    report_status_js = (STATIC_JS / "report_status.js").read_text(encoding="utf-8")
    assert "'alert'" in report_status_js
    assert "'assertive'" in report_status_js


def test_rejected_scan_requests_are_surfaced_to_the_user():
    """The server answers invalid targets and busy scanners with `scan_error`."""
    scan_runtime = (STATIC_JS / "scan_runtime.js").read_text(encoding="utf-8")
    assert "socket.on('scan_error'" in scan_runtime
    handler = scan_runtime[scan_runtime.index("socket.on('scan_error'"):]
    assert "showReportStatus(message, 'error')" in handler[:600]


def test_pause_and_resume_start_disabled_and_carry_their_job_state():
    """Pause/resume are backed by a job model now; before a scan they are disabled (exposed to assistive tech
    through the native `disabled` attribute) and the page drives them through data-pause-state."""
    elements = _elements()
    for button_id in ("suspend-scan-btn", "resume-scan-btn"):
        tag, attrs = _by_id(elements, button_id)
        assert tag == "button"
        assert "disabled" in attrs
        assert attrs.get("data-pause-state") == "idle"


def test_target_format_help_is_a_keyboard_reachable_button():
    elements = _elements()
    tag, attrs = _by_id(elements, "info-icon")
    assert tag == "button"
    assert attrs.get("type") == "button"
    assert attrs.get("aria-expanded") == "false"
    assert attrs.get("aria-controls") == "tooltip"


def test_results_table_has_an_empty_state_and_a_caption():
    template = TEMPLATE.read_text(encoding="utf-8")
    elements = _elements()
    _, empty_state = _by_id(elements, "discovery-empty-state")
    assert "hidden" not in (empty_state.get("class") or "").split()
    _, table = _by_id(elements, "discovery-table")
    assert "hidden" in (table.get("class") or "").split()
    assert re.search(r"<caption[^>]*sr-only[^>]*>", template)
    discovery_ui = (STATIC_JS / "discovery_ui.js").read_text(encoding="utf-8")
    assert "function syncDiscoveryEmptyState" in discovery_ui
    assert "childList: true" in discovery_ui


def test_only_one_module_drives_the_header_clock():
    layout_runtime = (STATIC_JS / "layout_runtime.js").read_text(encoding="utf-8")
    site_chrome = (STATIC_JS / "site_chrome.js").read_text(encoding="utf-8")
    assert "current-date-time" in layout_runtime
    assert "setInterval(updateDateTime" not in site_chrome


def test_dark_mode_layer_recolours_dialog_panels():
    elementary = (ROOT / "static" / "css" / "elementary.css").read_text(encoding="utf-8")
    assert "html .modal-panel { background: var(--e-surface); color: var(--e-text); }" in elementary


def test_skip_link_targets_the_scan_controls():
    template = TEMPLATE.read_text(encoding="utf-8")
    assert '<a href="#scan-target" class="skip-link">' in template
    assert ".skip-link:focus" in template
