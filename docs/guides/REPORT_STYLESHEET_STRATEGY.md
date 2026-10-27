# Report Stylesheet Strategy

## Current Direction

NmapUI uses a shared visual language across HTML and PDF reports, with an intentional split between:

- `nmap-modern.xsl` for the interactive browser report
- `nmap-pdf-olive-legacy.xsl` for the print-first PDF HTML

This is not a full fork in design language. It is a print-safe variant of the same report structure.

## What Should Stay Shared

Both report modes should preserve the same core report landmarks and visual identity:

- olive color system
- Instrument Serif and Inter typography
- primary report sections such as:
  - `#scannedhosts`
  - `#openservices`
  - `#onlinehosts`
- the same host, service, and vulnerability content ordering where practical

## Intentional Differences

The browser report uses a first-party, self-contained runtime and compiled CSS:

- no CDN scripts or stylesheets
- a CSP-hash-authorized runtime for filtering, sorting, highlighting, CSV export,
  and collapsible hosts
- compiled Tailwind CSS embedded in the generated report so saved reports work
  offline and do not depend on the app's static route

The PDF stylesheet should remain print-first:

- no interactive JavaScript dependencies
- the same embedded compiled CSS, constrained by PDF-specific styles
- predictable print layout and page breaks
- Playwright PDF rendering under `print` media

## Regression Expectations

Changes to either stylesheet should preserve:

- shared landmark sections in rendered HTML
- matching representative host/service content in both outputs
- absence of CDN/DataTables/jQuery assets in either generated report
- operation of the hash-authorized browser runtime without executing report data
- severity totals derived from structured Vulners CVSS entries in port scripts
- an explicit caveat that an empty external lookup result does not prove a host
  is vulnerability-free

Representative regression coverage lives in:

- `tests/test_reporting_modules.py`
- `tests/test_runtime_contract.py`
