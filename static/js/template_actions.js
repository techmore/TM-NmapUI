(function () {
    const actions = {
        showUpdateModal: () => window.showUpdateModal(),
        toggleLogPanel: () => window.toggleLogPanel(),
        hideCustomerForm: () => document.getElementById('add-customer-form')?.classList.add('hidden'),
        addCustomer: () => window.addCustomer(),
        hideHistoryModal: () => window.hideHistoryModal(),
        loadScanHistory: () => window.loadScanHistory(),
        hideAssetModal: () => document.getElementById('asset-modal')?.classList.add('hidden'),
        hideUpdateModal: () => window.hideUpdateModal(),
        startAppUpdate: () => window.startAppUpdate(),
        reloadPage: () => window.location.reload(),
        closeAssetDetailsModal: () => window.closeAssetDetailsModal(),
        showCustomerForm: () => window.showCustomerForm(),
        hideScanSummaryBanner: () => window.hideScanSummaryBanner(),
        hideAutoScanTimeModal: () => window.hideAutoScanTimeModal(),
        saveAutoScanTimes: () => window.saveAutoScanTimes(),
        saveAndRunScan: () => window.saveAndRunScan(),
        copyLog: (element) => window.copyLog({ target: element }),
        clearLog: () => window.clearLog(),
    };

    function dispatch(event) {
        const target = event.target instanceof Element
            ? event.target.closest('[data-action]')
            : null;
        if (!target || (target.dataset.actionEvent || 'click') !== event.type) {
            return;
        }

        const action = actions[target.dataset.action];
        if (action) {
            action(target);
        }
    }

    document.addEventListener('click', dispatch);
    document.addEventListener('change', dispatch);
})();
