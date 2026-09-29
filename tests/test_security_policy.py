import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_main_page_script_policy_does_not_need_inline_script_execution():
    template = (ROOT / "templates" / "index.html").read_text(encoding="utf-8")
    app_source = (ROOT / "app.py").read_text(encoding="utf-8")
    action_source = (ROOT / "static" / "js" / "template_actions.js").read_text(encoding="utf-8")

    script_tags = re.findall(r"<script\b([^>]*)>(.*?)</script\s*>", template, re.I | re.S)
    assert script_tags
    assert all(not contents.strip() for _attributes, contents in script_tags)
    assert re.search(r"\son[a-z]+\s*=", template, re.I) is None
    assert '<link rel="stylesheet" href="/static/css/tailwind.css" />' in template
    assert '<link rel="stylesheet" href="/static/vendor/fonts.css" />' in template
    assert '<script src="/static/vendor/socket.io.min.js"></script>' in template
    assert '<script src="/static/vendor/lucide.min.js"></script>' in template
    assert "https://cdnjs.cloudflare.com" not in template
    assert "https://cdn.tailwindcss.com" not in template
    assert "https://unpkg.com" not in template
    assert "fonts.googleapis.com" not in template
    assert "fonts.gstatic.com" not in template
    assert '<script src="/static/js/template_actions.js"></script>' in template
    assert "data-action" in template
    assert "document.addEventListener('click', dispatch)" in action_source
    assert (ROOT / "static" / "css" / "tailwind.css").is_file()
    assert (ROOT / "static" / "vendor" / "socket.io.min.js").is_file()
    assert (ROOT / "static" / "vendor" / "lucide.min.js").is_file()
    assert (ROOT / "static" / "vendor" / "fonts.css").is_file()
    assert (ROOT / "static" / "vendor" / "fonts" / "files").is_dir()
    assert (ROOT / "static" / "vendor" / "licenses" / "@fontsource-variable-inter.LICENSE.txt").is_file()
    assert (ROOT / "static" / "vendor" / "licenses" / "@fontsource-instrument-serif.LICENSE.txt").is_file()
    assert (ROOT / "static" / "vendor" / "licenses").is_dir()

    font_css = (ROOT / "static" / "vendor" / "fonts.css").read_text(encoding="utf-8")
    assert "font-family: 'Inter'" in font_css
    assert "font-family: 'Instrument Serif'" in font_css
    assert "https://" not in font_css
    assert "fonts.googleapis.com" not in app_source
    assert "fonts.gstatic.com" not in app_source
    for xsl_name in ("nmap-modern.xsl", "nmap-pdf-olive-legacy.xsl"):
        xsl = (ROOT / xsl_name).read_text(encoding="utf-8")
        assert "fonts.googleapis.com" not in xsl
        assert "fonts.gstatic.com" not in xsl

    script_policy = re.search(r'"script-src ([^"]+)"', app_source)
    assert script_policy is not None
    assert script_policy.group(1) == "'self'"
    for directive in (
        "base-uri 'self'",
        "object-src 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ):
        assert f'"{directive}"' in app_source
