# Frontend Layout Guide

This page has a small set of layout rules. New sections should follow these instead of introducing one-off wrapper combinations.

## Canonical Containers

- `page-shell`
  - Use for the primary page-width wrapper.
  - Standard width: `max-width: 80rem`.
  - Standard horizontal padding: `1rem`, `1.5rem` from `sm`, `2rem` from `lg`.
- Modal shells
  - Keep modal width local to the modal component.
  - Use one width rule per modal (`max-w-md`, `max-w-2xl`, `max-w-4xl`, `max-w-6xl`) instead of nesting another page-width wrapper inside the modal body.
  - Share overlay and base panel structure through common modal classes instead of repeating the full fixed/flex/background shell inline.
- Full-width bands
  - Keep them inside `page-shell` unless the section is intentionally edge-to-edge.
  - Prefer section-level spacing and borders over adding another max-width wrapper.
- Breakout data sections
  - Use a local band class inside `page-shell` when the content itself needs horizontal scrolling.
  - Keep the band responsible for border, background, and overflow; keep the shell responsible for page alignment.
- Form controls
  - Use shared form-control classes for repeated modal/filter inputs.
  - Keep only exceptional hero controls on bespoke class stacks when they have intentionally different visual weight.
- Header actions
  - Reuse a shared icon-button class for modal close actions and similar header affordances.
  - Keep per-button sizing local with utility classes such as `size-8` or `size-10`.
- Standard actions
  - Use shared action-button classes for repeated modal/footer actions.
  - Keep intent local by choosing between primary and secondary variants instead of rewriting the full olive button stack inline.
  - Use a compact size helper when a shared action button needs smaller control-row sizing.

## Rules

- Do not repeat `mx-auto max-w-7xl px-4 sm:px-6 lg:px-8` inline. Use `page-shell`.
- Do not nest multiple page-width wrappers inside one another.
- Keep section spacing consistent before adding custom width rules.
- For oversized tables, keep `page-shell` outside and put `overflow-x-auto` on the inner band.
- For modals, keep `modal-overlay` and `modal-panel` shared, and only vary width, borders, or scroll behavior per modal.
- For standard inputs and selects, prefer `form-control` plus a size class instead of repeating border/padding/focus utilities inline.
- For modal close buttons, use `icon-button` instead of repeating text-color hover stacks.
- For modal/footer action buttons, use `action-button` with an intent variant instead of repeating the olive background stack.
- For smaller action rows such as history filters, add a shared size helper instead of inline text-size/padding overrides.
- If a section needs a custom width, document why it is not using `page-shell`.

## Accessibility Conventions

- The section switcher is a WAI-ARIA tab strip: `role="tablist"` on the button row, `role="tab"` +
  `aria-controls` on each button, `role="tabpanel"` + `aria-labelledby` on each panel. Only the
  selected tab has `tabindex="0"`; arrow keys, Home and End move between tabs
  (`initializeTabListKeyboard` in `static/js/site_chrome.js`). `setTabButtonState` owns
  `aria-selected`; do not toggle it elsewhere.
- Every `.modal-overlay` is a `role="dialog" aria-modal="true"` element labelled by its heading id.
  `static/js/modal_a11y.js` handles Escape, Tab trapping and focus restore for all of them by
  watching the `hidden` class, so new dialogs only need the markup and a close control whose
  `data-action` starts with `hide` or `close`.
- `#report-status` is a live region: `showReportStatus` switches it between `role="status"`
  (progress, success) and `role="alert"` (errors). Tab status boxes are `aria-live="polite"`.
- Server rejections arrive as `scan_error`; `static/js/scan_runtime.js` renders them through
  `showReportStatus(message, 'error')` and mirrors them into the audit log.
- The results table starts hidden behind `#discovery-empty-state`; `syncDiscoveryEmptyState`
  in `static/js/discovery_ui.js` swaps them whenever the `tbody` gains or loses rows.
- Controls that exist in the layout without a backend (Pause/Resume, issue #10) stay in the DOM but
  are `disabled`, `aria-disabled="true"` and carry a `title` that says why.
- `static/css/elementary.css` is the dark-mode layer; any new component with a hard-coded white
  or olive background needs a `var(--e-surface)` / `var(--e-text)` override there.

## Current Standard

- The main page shell in [`templates/index.html`](../../templates/index.html) is the canonical example.
- The discovery table section in [`templates/index.html`](../../templates/index.html) is the canonical breakout-band example.
- The modal wrappers in [`templates/index.html`](../../templates/index.html) are the canonical modal-shell example.
- The customer/history/auto-scan inputs in [`templates/index.html`](../../templates/index.html) are the canonical shared form-control example.
- Follow this guide for future layout refactors tied to [#74](https://github.com/techmore/TM-NmapUI/issues/74).
