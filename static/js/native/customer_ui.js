let customersTabInitialized = false;

function setCustomerTabStatus(message, isError = false) {
    const status = document.getElementById('customers-tab-status');
    if (!status) return;
    if (!message) {
        status.textContent = '';
        status.classList.add('hidden');
        return;
    }
    status.textContent = message;
    status.classList.remove('hidden');
    status.classList.toggle('bg-red-50', isError);
    status.classList.toggle('text-red-700', isError);
    status.classList.toggle('bg-olive-50', !isError);
    status.classList.toggle('text-olive-800', !isError);
}

function loadLocalCustomers() {
    try {
        return JSON.parse(localStorage.getItem('gemini-nmap-customers') || '[]');
    } catch (error) {
        return [];
    }
}

function saveLocalCustomers(customers) {
    localStorage.setItem('gemini-nmap-customers', JSON.stringify(customers));
}

function normalizeCustomerMatchValue(value) {
    return String(value || '').trim().toLowerCase();
}

function getCurrentNetworkCustomerSignals(profile = window.currentCustomerProfile || {}) {
    return new Set([
        profile.prefix,
        profile.baseName,
        profile.reportLabel,
        profile.folderName,
        profile.fingerprint,
        profile.publicIP,
        document.getElementById('scan-target')?.value,
        document.getElementById('cidr-value')?.textContent,
        document.getElementById('public-ip-value')?.textContent,
        document.getElementById('local-ip-value')?.textContent
    ].map(normalizeCustomerMatchValue).filter(Boolean));
}

function customerMatchesCurrentNetwork(customer, signals) {
    const fields = [customer.id, customer.name, customer.target, customer.publicIP, customer.folderName, customer.fingerprint];
    return fields.some(field => {
        const value = normalizeCustomerMatchValue(field);
        if (!value) return false;
        if (signals.has(value)) return true;
        return Array.from(signals).some(signal => signal && (value.includes(signal) || signal.includes(value)));
    });
}

function syncCustomerSelectors(profile = window.currentCustomerProfile || {}) {
    const customers = loadLocalCustomers();
    const profileId = profile.fingerprint || profile.folderName ? `profile:${profile.fingerprint || profile.folderName}` : '';
    const currentProfileCustomer = profileId ? {
        id: profileId,
        name: profile.prefix || profile.baseName || profile.reportLabel || 'Current Network',
        target: profile.publicIP || profile.folderName || ''
    } : null;
    const selectors = [
        document.getElementById('customer-quick-add'),
        document.getElementById('current-customer'),
        document.getElementById('settings-profile-customer')
    ].filter(Boolean);
    const signals = getCurrentNetworkCustomerSignals(profile);
    const matchedCustomer = customers.find(customer => customerMatchesCurrentNetwork(customer, signals));
    const selectedCustomer = matchedCustomer || currentProfileCustomer;

    selectors.forEach(select => {
        const previousValue = select.value;
        const placeholder = select.id === 'settings-profile-customer'
            ? 'Use current customer selection'
            : 'Unassigned Network';
        select.replaceChildren(new Option(placeholder, ''));
        if (currentProfileCustomer && !matchedCustomer) {
            select.appendChild(new Option(currentProfileCustomer.name, currentProfileCustomer.id));
        }
        customers.forEach(customer => {
            select.appendChild(new Option(customer.name || customer.target || 'Unnamed Customer', customer.id));
        });
        select.value = selectedCustomer?.id || previousValue || '';
    });

    window.currentMatchedCustomerId = selectedCustomer?.id || selectors[0]?.value || 'unknown';
}

function escapeCustomerHTML(value) {
    return String(value).replace(/[&<>"']/g, char => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[char]);
}

function renderCustomerFingerprint(profile) {
    if (!profile) return;
    window.currentCustomerProfile = profile;
    const prefixInput = document.getElementById('customer-profile-prefix');
    const summary = document.getElementById('customer-fingerprint-summary');
    const folder = document.getElementById('customer-fingerprint-folder');

    if (prefixInput && !prefixInput.value) prefixInput.value = profile.prefix || 'CSP';
    if (summary) {
        summary.textContent = `${profile.reportLabel || profile.baseName || 'CSP_(unknown_wan)'} | ${profile.fingerprint || 'pending'} | WAN ${profile.publicIP || 'Unknown'}`;
    }
    if (folder) {
        folder.textContent = `Reports folder: reports_archive/${profile.folderName || 'pending'}`;
    }
    syncCustomerSelectors(profile);
}

function renderCustomersTab(customers = loadLocalCustomers()) {
    const list = document.getElementById('customers-tab-list');
    syncCustomerSelectors();
    if (!list) return;
    list.replaceChildren();

    if (!customers.length) {
        setCustomerTabStatus('No customers configured in this browser yet.');
        return;
    }

    setCustomerTabStatus('');
    customers.forEach(customer => {
        const card = document.createElement('div');
        card.className = 'rounded-2xl border border-olive-200 bg-white p-5 shadow-sm';
        card.innerHTML = `
            <div class="flex items-start justify-between gap-4">
                <div>
                    <h3 class="text-lg font-bold text-olive-950">${escapeCustomerHTML(customer.name)}</h3>
                    <p class="mt-1 font-mono text-xs text-olive-600">${escapeCustomerHTML(customer.target || 'No target saved')}</p>
                </div>
                <button type="button" class="delete-customer-btn action-button action-button-secondary action-button-compact" data-id="${escapeCustomerHTML(customer.id)}">Delete</button>
            </div>
        `;
        list.appendChild(card);
    });
}

function loadCustomersTab() {
    renderCustomersTab();
    window.socket?.emit('get_customer_profile');
}

function showCustomerForm() {
    const name = prompt('Customer name');
    if (!name) return;
    const target = prompt('Default target or public IP', document.getElementById('scan-target')?.value || '') || '';
    const customers = loadLocalCustomers();
    customers.unshift({ id: String(Date.now()), name, target });
    saveLocalCustomers(customers);
    renderCustomersTab(customers);
    syncCustomerSelectors();
}

function getSelectedCustomerProfilePrefix() {
    const selectedId = document.getElementById('customer-quick-add')?.value || window.currentMatchedCustomerId || '';
    if (!selectedId || selectedId.startsWith('profile:')) return window.currentCustomerProfile?.prefix || '';
    const customer = loadLocalCustomers().find(item => item.id === selectedId);
    return customer?.prefix || customer?.name || '';
}

function initializeCustomerUI() {
    if (customersTabInitialized) return;
    customersTabInitialized = true;

    document.getElementById('refresh-customers-tab-btn')?.addEventListener('click', loadCustomersTab);
    document.getElementById('add-customer-tab-btn')?.addEventListener('click', showCustomerForm);
    document.getElementById('save-customer-prefix-btn')?.addEventListener('click', () => {
        const prefix = document.getElementById('customer-profile-prefix')?.value || 'CSP';
        window.socket?.emit('set_customer_profile_prefix', { prefix });
        setCustomerTabStatus('Customer report prefix saved.');
    });
    document.getElementById('customer-quick-add')?.addEventListener('change', event => {
        window.currentMatchedCustomerId = event.target.value || 'unknown';
        const hiddenSelector = document.getElementById('current-customer');
        if (hiddenSelector) hiddenSelector.value = event.target.value;
    });
    window.socket?.on('customer_profile', renderCustomerFingerprint);
    document.getElementById('customers-tab-list')?.addEventListener('click', event => {
        const button = event.target.closest('.delete-customer-btn');
        if (!button) return;
        const customers = loadLocalCustomers().filter(customer => customer.id !== button.dataset.id);
        saveLocalCustomers(customers);
        renderCustomersTab(customers);
        syncCustomerSelectors();
    });
    syncCustomerSelectors();
}

window.initializeCustomerUI = initializeCustomerUI;
window.loadCustomersTab = loadCustomersTab;
window.showCustomerForm = showCustomerForm;
window.renderCustomerFingerprint = renderCustomerFingerprint;
window.syncCustomerSelectors = syncCustomerSelectors;
window.getSelectedCustomerProfilePrefix = getSelectedCustomerProfilePrefix;
