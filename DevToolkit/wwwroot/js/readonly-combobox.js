(function () {
    const allowedKeys = new Set(['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight', 'Home', 'End', 'Tab', 'Enter', 'Escape']);
    let observerStarted = false;

    const blockInput = (event) => {
        if (event.type === 'beforeinput') {
            event.preventDefault();
            return;
        }

        if (event.type === 'keydown') {
            if (event.key && (event.key.length === 1 || !allowedKeys.has(event.key))) {
                event.preventDefault();
            }
        }
    };

    const applyReadOnly = (combo) => {
        if (!combo || combo.__readonlyApplied) {
            return;
        }

        combo.__readonlyApplied = true;

        const ensureInputState = () => {
            const input = combo.shadowRoot?.querySelector('input');
            if (!input) {
                return;
            }

            if (!input.hasAttribute('readonly')) {
                input.setAttribute('readonly', 'readonly');
            }

            input.addEventListener('beforeinput', blockInput);
            input.addEventListener('keydown', blockInput);
        };

        ensureInputState();

        if (combo.shadowRoot) {
            const shadowObserver = new MutationObserver(ensureInputState);
            shadowObserver.observe(combo.shadowRoot, { childList: true, subtree: true });
        }
    };

    const initializeAll = () => {
        document.querySelectorAll('fluent-combobox.readonly-combo').forEach(applyReadOnly);
    };

    const startObserver = () => {
        if (observerStarted) {
            initializeAll();
            return;
        }

        observerStarted = true;
        initializeAll();

        const domObserver = new MutationObserver(initializeAll);
        domObserver.observe(document.body, { childList: true, subtree: true });
    };

    window.devToolkitReadonlyCombobox = window.devToolkitReadonlyCombobox || {
        init: () => {
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', startObserver, { once: true });
            } else {
                startObserver();
            }
        }
    };
})();
