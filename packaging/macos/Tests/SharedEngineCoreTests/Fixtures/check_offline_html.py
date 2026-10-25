"""Check actual exported files in Chromium; all HTTP(S) attempts are intercepted."""
import json
import base64
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright

root = Path(sys.argv[1]).resolve(strict=True)
with sync_playwright() as playwright:
    browser = playwright.chromium.launch()
    context = browser.new_context(viewport={"width": 1440, "height": 1000}, reduced_motion="reduce", accept_downloads=True)
    requests = []

    def intercept(route):
        if route.request.url.startswith(("http:", "https:")):
            requests.append(route.request.url)
            route.abort()
        else:
            route.continue_()

    context.route("**/*", intercept)
    for name in ("comment", "rawtext", "header", "attribute"):
        page = context.new_page()
        page.goto((root / f"adversarial-{name}.html").as_uri())
        page.wait_for_timeout(100)
        assert page.evaluate("window.__canary === undefined"), name
        assert page.locator('meta[http-equiv="Content-Security-Policy"]').count() >= 2, name
        page.close()

    observations = []
    for name in ("canonical-baseline", "canonical-offline"):
        page = context.new_page()
        page.goto((root / f"{name}.html").as_uri())
        page.get_by_role("searchbox", name="Filter table-services", exact=True).wait_for()
        page.add_style_tag(content="*,*::before,*::after{animation:none!important;transition:none!important}.fade-in{opacity:1!important;transform:none!important}")
        page.wait_for_timeout(100)
        observations.append(page.evaluate("({mode:document.compatMode,text:document.body.innerText,height:document.body.scrollHeight,width:document.body.scrollWidth})"))
        page.screenshot(path=str(root / f"{name}.png"), full_page=True)
        search = page.get_by_role("searchbox", name="Filter table-services", exact=True)
        search.fill("no-matching-service")
        assert page.locator("#table-services tbody tr:visible").count() == 0
        search.fill("")
        assert page.locator("#table-services tbody tr:visible").count() > 0
        with page.expect_download() as result:
            page.locator("#table-services").locator("xpath=preceding-sibling::*[1]").get_by_role("button", name="Download CSV", exact=True).click()
        assert result.value.suggested_filename == "table-services.csv"
        page.close()
    assert observations[0] == observations[1], "Offline protection changed report layout/text"
    assert not requests, "Offline report attempted an HTTP(S) request"
    # External viewers do not apply HTTP-only sandbox flags from meta CSP.
    # Preserve this boundary explicitly: navigation can occur, but the client
    # must never serialize/forward its engine authorization to that viewer.
    sensitive = ["fixture-contraseña-🔐", base64.b64encode("fixture-user:fixture-contraseña-🔐".encode()).decode()]
    for name in ("canonical-offline.html", "adversarial-comment.html"):
        text = (root / name).read_text()
        assert all(secret not in text for secret in sensitive)
    navigation = (root / "adversarial-comment.html").read_text().replace(
        "</body>", '<meta http-equiv="refresh" content="0;url=http://127.0.0.1:9/offline-navigation-canary"></body>')
    navigation_path = root / "navigation-boundary.html"
    navigation_path.write_text(navigation)
    boundary = []
    def intercept_navigation(route):
        if route.request.url.startswith(("http:", "https:")):
            headers = route.request.all_headers()
            boundary.append({"authorization_present": "authorization" in headers,
                             "credential_present": any(secret in json.dumps(headers) + route.request.url for secret in sensitive)})
            route.abort()  # No request reaches even the loopback canary port.
        else:
            route.continue_()
    context.unroute("**/*", intercept)
    context.route("**/*", intercept_navigation)
    page = context.new_page()
    page.goto(navigation_path.as_uri())
    page.wait_for_timeout(250)
    assert boundary == [{"authorization_present": False, "credential_present": False}]
    browser.close()
print(json.dumps({"adversarial_scripts_blocked": 4, "canonical_layout_equal": True, "hashed_runtime_filter_csv": True,
                  "script_subresource_http_requests": 0, "viewer_navigation_intercepted": 1, "navigation_engine_credentials": False}))
