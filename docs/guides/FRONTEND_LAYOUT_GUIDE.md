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

## Current Standard

- The main page shell in [`templates/index.html`](../../templates/index.html) is the canonical example.
- The discovery table section in [`templates/index.html`](../../templates/index.html) is the canonical breakout-band example.
- The modal wrappers in [`templates/index.html`](../../templates/index.html) are the canonical modal-shell example.
- The customer/history/auto-scan inputs in [`templates/index.html`](../../templates/index.html) are the canonical shared form-control example.
- Follow this guide for future layout refactors tied to [#74](https://github.com/techmore/TM-NmapUI/issues/74).
