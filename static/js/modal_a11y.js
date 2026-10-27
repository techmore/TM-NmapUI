// Shared keyboard and focus behaviour for every `.modal-overlay` dialog.
//
// The dialogs are plain divs toggled with the `hidden` class by their own
// modules, so this file does not open or close anything itself. It watches
// the class attribute and, when a dialog becomes visible, moves focus inside
// it; when it closes, focus returns to the control that opened it. Escape
// closes the top-most open dialog through its own close control, and Tab is
// kept inside the open dialog.
(function () {
    const FOCUSABLE = [
        'a[href]',
        'button:not([disabled])',
        'input:not([disabled]):not([type="hidden"])',
        'select:not([disabled])',
        'textarea:not([disabled])',
        '[tabindex]:not([tabindex="-1"])',
    ].join(',');

    const openers = new WeakMap();

    function isVisible(overlay) {
        return !overlay.classList.contains('hidden');
    }

    function focusableIn(overlay) {
        return Array.from(overlay.querySelectorAll(FOCUSABLE)).filter((element) => {
            if (element.closest('.hidden') && element.closest('.hidden') !== overlay) return false;
            return element.offsetWidth > 0 || element.offsetHeight > 0 || element === document.activeElement;
        });
    }

    function openOverlays() {
        return Array.from(document.querySelectorAll('.modal-overlay')).filter(isVisible);
    }

    function topOverlay() {
        const open = openOverlays();
        return open.length ? open[open.length - 1] : null;
    }

    function closeControl(overlay) {
        return overlay.querySelector(
            '[data-action^="hide"], [data-action^="close"], [aria-label^="Close"]'
        );
    }

    function onOpened(overlay) {
        const active = document.activeElement;
        if (active && active !== document.body && !overlay.contains(active)) {
            openers.set(overlay, active);
        }
        // Let the opening module finish rendering before we move focus.
        window.setTimeout(() => {
            if (!isVisible(overlay) || overlay.contains(document.activeElement)) return;
            const candidates = focusableIn(overlay);
            const preferred = candidates.find((element) => !closeControl(overlay) || element !== closeControl(overlay));
            const target = preferred || candidates[0] || overlay.querySelector('.modal-panel') || overlay;
            if (!target.hasAttribute('tabindex') && !candidates.includes(target)) {
                target.setAttribute('tabindex', '-1');
            }
            target.focus({ preventScroll: true });
        }, 0);
    }

    function onClosed(overlay) {
        const opener = openers.get(overlay);
        openers.delete(overlay);
        if (opener && opener.isConnected && typeof opener.focus === 'function' && !opener.closest('.hidden')) {
            opener.focus({ preventScroll: true });
        }
    }

    function observe(overlay) {
        if (overlay.dataset.modalA11y === 'true') return;
        overlay.dataset.modalA11y = 'true';
        let wasVisible = isVisible(overlay);
        const observer = new MutationObserver(() => {
            const visible = isVisible(overlay);
            if (visible === wasVisible) return;
            wasVisible = visible;
            if (visible) onOpened(overlay); else onClosed(overlay);
        });
        observer.observe(overlay, { attributes: true, attributeFilter: ['class'] });
    }

    function onKeydown(event) {
        const overlay = topOverlay();
        if (!overlay) return;

        if (event.key === 'Escape') {
            const control = closeControl(overlay);
            if (control) {
                event.preventDefault();
                control.click();
            }
            return;
        }

        if (event.key === 'Tab') {
            const items = focusableIn(overlay);
            if (!items.length) {
                event.preventDefault();
                return;
            }
            const first = items[0];
            const last = items[items.length - 1];
            const current = document.activeElement;
            if (!overlay.contains(current)) {
                event.preventDefault();
                (event.shiftKey ? last : first).focus();
            } else if (event.shiftKey && current === first) {
                event.preventDefault();
                last.focus();
            } else if (!event.shiftKey && current === last) {
                event.preventDefault();
                first.focus();
            }
        }
    }

    function initializeModalAccessibility() {
        document.querySelectorAll('.modal-overlay').forEach(observe);
        document.addEventListener('keydown', onKeydown);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeModalAccessibility, { once: true });
    } else {
        initializeModalAccessibility();
    }

    window.initializeModalAccessibility = initializeModalAccessibility;
})();
