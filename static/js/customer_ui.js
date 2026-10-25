let customersTabLoaded = false;
let customerFormMode = 'add';
let editingCustomerId = null;
let customerAutoMonitorState = { defaults: null, rules: [] };

function getAutoMonitorRule(customer) {
    const customerId = String(customer?.id || '');
    return (customerAutoMonitorState.rules || []).find(
        (rule) => String(rule.customer_id || '') === customerId
    ) || null;
}

function getDefaultAutoMonitorRule(customer) {
    const defaults = customerAutoMonitorState.defaults || {
        enabled_by_default: false,
        recurrence: 'weekly',
        day_of_week: 'sunday',
        time: '01:00',
        scan_mode: 'complete_pdf',
    };
    return {
        enabled: defaults.enabled_by_default,
        recurrence: defaults.recurrence,
        day_of_week: defaults.day_of_week,
        time: defaults.time,
        target: customer?.networks?.public_ip && customer.networks.public_ip !== 'dynamic'
            ? customer.networks.public_ip
            : '',
        next_run: null,
    };
}

async function loadAutoMonitorSettings() {
    const response = await fetch('/api/settings/auto-monitor', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
        throw new Error(`Auto-monitor settings request failed with HTTP ${response.status}`);
    }
    customerAutoMonitorState = await response.json();
    return customerAutoMonitorState;
}

async function saveAutoMonitorRule(customer, updates) {
    const settingsResponse = await fetch('/api/settings', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
    });
    if (!settingsResponse.ok) {
        throw new Error(`Settings request failed with HTTP ${settingsResponse.status}`);
    }

    const currentSettings = await settingsResponse.json();
    const nextSettings = structuredClone(currentSettings || {});
    const defaults = nextSettings.auto_monitor?.defaults
        || customerAutoMonitorState.defaults
        || {};
    const rules = Array.isArray(nextSettings.auto_monitor?.rules)
        ? nextSettings.auto_monitor.rules.slice()
        : [];
    const customerId = String(customer.id || '');
    const existingIndex = rules.findIndex(
        (rule) => String(rule.customer_id || '') === customerId
    );
    const baseRule = existingIndex >= 0
        ? rules[existingIndex]
        : {
            customer_id: customerId,
            customer_name: customer.name || '',
            enabled: Boolean(defaults.enabled_by_default),
            recurrence: defaults.recurrence || 'weekly',
            day_of_week: defaults.day_of_week || 'sunday',
            time: defaults.time || '01:00',
            scan_mode: 'complete_pdf',
            target: customer.networks?.public_ip && customer.networks.public_ip !== 'dynamic'
                ? customer.networks.public_ip
                : '',
            public_ip: customer.networks?.public_ip || '',
        };

    const nextRule = {
        ...baseRule,
        ...updates,
        customer_id: customerId,
        customer_name: customer.name || '',
        public_ip: customer.networks?.public_ip || baseRule.public_ip || '',
        scan_mode: 'complete_pdf',
    };

    if (!nextSettings.auto_monitor) {
        nextSettings.auto_monitor = { defaults, rules: [] };
    }
    if (existingIndex >= 0) {
        rules[existingIndex] = nextRule;
    } else {
        rules.push(nextRule);
    }
    nextSettings.auto_monitor.defaults = defaults;
    nextSettings.auto_monitor.rules = rules;

    const saveResponse = await fetch('/api/settings', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            Accept: 'application/json',
        },
        body: JSON.stringify(nextSettings),
    });
    if (!saveResponse.ok) {
        throw new Error(`Settings save failed with HTTP ${saveResponse.status}`);
    }

    const saved = await saveResponse.json();
    customerAutoMonitorState = saved.settings.auto_monitor || customerAutoMonitorState;
    return customerAutoMonitorState;
}

function showCustomerForm(mode = 'add') {
    customerFormMode = mode;
    if (mode !== 'edit') {
        editingCustomerId = null;
    }
    const title = document.querySelector('#add-customer-form h3');
    if (title) title.textContent = mode === 'edit' ? 'Edit Customer' : 'Add Customer';
    document.getElementById('add-customer-form').classList.remove('hidden');
}

function hideCustomerForm() {
    document.getElementById('add-customer-form').classList.add('hidden');
}

function setCustomerTabStatus(message, isError = false) {
    const status = document.getElementById('customers-tab-status');
    if (!status) {
        return;
    }

    if (!message) {
        status.textContent = '';
        status.classList.add('hidden');
        status.classList.remove('bg-red-50', 'text-red-700', 'bg-olive-50', 'text-olive-800');
        return;
    }

    status.textContent = message;
    status.classList.remove('hidden');
    status.classList.remove('bg-red-50', 'text-red-700', 'bg-olive-50', 'text-olive-800');
    status.classList.add(isError ? 'bg-red-50' : 'bg-olive-50');
    status.classList.add(isError ? 'text-red-700' : 'text-olive-800');
}

function showCustomerMessage(message, type = 'info') {
    const messagesDiv = document.getElementById('customer-messages');
    const messageSpan = document.getElementById('customer-message');

    messagesDiv.classList.remove('hidden');
    messageSpan.textContent = message;

    messagesDiv.firstElementChild.className = `p-3 border rounded-lg text-sm ${
        type === 'error' ? 'bg-red-100 border-red-300 text-red-800' :
        type === 'success' ? 'bg-green-100 border-green-300 text-green-800' :
        'bg-yellow-100 border-yellow-300 text-yellow-800'
    }`;

    setTimeout(() => {
        messagesDiv.classList.add('hidden');
    }, 5000);
}

function populateCustomerDropdown(customers) {
    console.log('Populating customer dropdowns with', customers.length, 'customers');

    const mainDropdown = document.getElementById('current-customer');
    const quickAddDropdown = document.getElementById('customer-quick-add');

    if (!quickAddDropdown) return;

    const unassignedOption = () => {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'Unassigned';
        return option;
    };

    quickAddDropdown.replaceChildren(unassignedOption());
    if (mainDropdown) {
        mainDropdown.replaceChildren(unassignedOption());
    }

    customers.forEach(customer => {
        const customerId = String(customer.id);
        const customerName = customer.name;

        if (!customerId || !customerName) return;

        if (mainDropdown) {
            const mainOption = document.createElement('option');
            mainOption.value = customerId;
            mainOption.textContent = customerName;
            if (customerId === 'unknown') mainOption.classList.add('hidden');
            mainDropdown.appendChild(mainOption);
        }

        const quickOption = document.createElement('option');
        quickOption.value = customerId;
        quickOption.textContent = customerName;
        if (customerId === 'unknown') quickOption.classList.add('hidden');
        quickAddDropdown.appendChild(quickOption);
    });

    const targetId = window.currentMatchedCustomerId || '';

    if (targetId) {
        console.log('Applying target customer selection:', targetId);
        quickAddDropdown.value = targetId;
        if (mainDropdown) mainDropdown.value = targetId;
        updateHistoryBadge(targetId);
    } else {
        updateHistoryBadge('');
    }
}

function updateDropdownSelection(customerId, customerName) {
    const idToSelect = customerId ? String(customerId) : '';
    const quickAddDropdown = document.getElementById('customer-quick-add');
    if (quickAddDropdown) {
        quickAddDropdown.value = idToSelect;
        console.log(`Dropdown updated to customer ID: ${idToSelect}, Name: ${customerName}`);
        updateHistoryBadge(customerName);
    }

    const mainDropdown = document.getElementById('current-customer');
    if (mainDropdown) {
        mainDropdown.value = idToSelect;
    }
}

function updateCustomerSelection(customer) {
    const dropdown = document.getElementById('current-customer');

    if (!dropdown) {
        console.log('current-customer dropdown not found, skipping update');
        return;
    }

    if (customer.id && customer.name) {
        const tllDiv = document.getElementById('last-scan-duration');
        if (tllDiv) {
            if (customer.metadata && customer.metadata.last_scan_duration) {
                tllDiv.textContent = 'TLL: ' + customer.metadata.last_scan_duration;
                tllDiv.classList.remove('hidden');
            } else {
                tllDiv.classList.add('hidden');
            }
        }

        let customerExists = false;
        for (let option of dropdown.options) {
            if (option.value === customer.id) {
                option.textContent = `${customer.name} (${customer.confidence.toFixed(2)} confidence)`;
                customerExists = true;
                break;
            }
        }

        if (!customerExists) {
            const option = document.createElement('option');
            option.value = customer.id;
            option.textContent = `${customer.name} (Manual Assignment)`;
            dropdown.appendChild(option);
        }

        dropdown.value = customer.id;
    } else {
        dropdown.value = '';
    }
}

function displayCustomerList(customers) {
    const customerList = customers.map(c =>
        `${c.name || c.get?.('name')} (ID: ${c.id || c.get?.('id')})`
    ).join('\n');

    showCustomerMessage(`Configured Customers:\n${customerList}`, 'info');
}

function addCustomer(socket) {
    const customerData = {
        customer_id: editingCustomerId,
        name: document.getElementById('cust-name').value,
        id: document.getElementById('cust-id').value,
        description: document.getElementById('cust-description').value,
        location: document.getElementById('cust-location').value,
        connection_type: document.getElementById('cust-connection-type').value,
        public_ip: document.getElementById('cust-public-ip').value,
        gateway_pattern: document.getElementById('cust-gateway').value,
        exit_pattern: document.getElementById('cust-exit-pattern').value,
        hop_count: document.getElementById('cust-hop-count').value,
        private_ranges: document.getElementById('cust-private-ranges').value,
        confidence: 0.7,
    };

    document.getElementById('cust-name').value = '';
    document.getElementById('cust-id').value = '';
    document.getElementById('cust-description').value = '';
    document.getElementById('cust-location').value = '';
    document.getElementById('cust-public-ip').value = '';
    document.getElementById('cust-gateway').value = '';
    document.getElementById('cust-exit-pattern').value = '';
    document.getElementById('cust-hop-count').value = '';
    document.getElementById('cust-private-ranges').value = '';

    hideCustomerForm();
    socket.emit(customerFormMode === 'edit' ? 'update_customer' : 'add_customer', customerData);
    customerFormMode = 'add';
    editingCustomerId = null;
}

function assignCustomer(socket) {
    const dropdown = document.getElementById('current-customer');
    const selectedId = dropdown.value;
    const selectedOption = dropdown.options[dropdown.selectedIndex];
    const selectedName = selectedOption?.textContent || '';

    if (!selectedId) {
        showCustomerMessage('Please select a customer to assign', 'error');
        return;
    }

    socket.emit('assign_customer', {
        customer_id: selectedId,
        customer_name: selectedName.split(' (')[0],
    });
}

function showCustomerList(socket) {
    socket.emit('get_customers');
}

function editCustomer(customer) {
    customerFormMode = 'edit';
    editingCustomerId = String(customer.id || '');
    document.getElementById('cust-name').value = customer.name || '';
    document.getElementById('cust-id').value = customer.id || '';
    document.getElementById('cust-description').value = customer.description || '';
    document.getElementById('cust-location').value = customer.metadata?.location || '';
    document.getElementById('cust-connection-type').value = customer.metadata?.connection_type?.[0] || customer.fingerprints?.[0]?.type || 'direct';
    document.getElementById('cust-public-ip').value = customer.networks?.public_ip || '';
    document.getElementById('cust-gateway').value = customer.networks?.gateway_pattern || '';
    document.getElementById('cust-exit-pattern').value = Array.isArray(customer.networks?.exit_ips) ? customer.networks.exit_ips.join(',') : '';
    document.getElementById('cust-hop-count').value = customer.fingerprints?.[0]?.hop_count || '';
    document.getElementById('cust-private-ranges').value = Array.isArray(customer.networks?.private_ranges) ? customer.networks.private_ranges.join(',') : '';
    showCustomerForm('edit');
}

function renderCustomersTab(customers) {
    const list = document.getElementById('customers-tab-list');
    if (!list) {
        return;
    }

    list.replaceChildren();
    const visibleCustomers = (customers || []).filter((customer) => customer?.id && customer.id !== 'unknown');

    if (!visibleCustomers.length) {
        setCustomerTabStatus('No customers configured yet.');
        return;
    }

    setCustomerTabStatus('');
    visibleCustomers.forEach((customer) => {
        const card = document.createElement('article');
        card.className = 'rounded-2xl border border-olive-200 bg-olive-50 p-4 shadow-sm';

        const title = document.createElement('h3');
        title.className = 'text-xl font-display italic text-olive-950';
        title.textContent = customer.name || 'Unknown';
        card.appendChild(title);

        const details = document.createElement('div');
        details.className = 'mt-3 space-y-1 text-sm text-olive-700';
        details.innerHTML = `
            <div><span class="font-semibold text-olive-900">ID:</span> <span class="font-mono">${customer.id || '--'}</span></div>
            <div><span class="font-semibold text-olive-900">Public IP:</span> <span class="font-mono">${customer.networks?.public_ip || '--'}</span></div>
            <div><span class="font-semibold text-olive-900">Public IPs:</span> <span class="font-mono">${Array.isArray(customer.networks?.public_ips) ? customer.networks.public_ips.join(', ') : '--'}</span></div>
            <div><span class="font-semibold text-olive-900">Exit IPs:</span> <span class="font-mono">${Array.isArray(customer.networks?.exit_ips) ? customer.networks.exit_ips.join(', ') : (customer.networks?.exit_ips || '--')}</span></div>
            <div><span class="font-semibold text-olive-900">Gateway:</span> <span class="font-mono">${customer.networks?.gateway_pattern || '--'}</span></div>
        `;
        card.appendChild(details);

        const autoMonitorRule = getAutoMonitorRule(customer) || getDefaultAutoMonitorRule(customer);
        const autoMonitor = document.createElement('section');
        autoMonitor.className = 'mt-4 rounded-2xl border border-olive-200 bg-white p-4';
        autoMonitor.innerHTML = `
            <div class="flex items-center justify-between gap-3">
                <div>
                    <h4 class="text-sm font-bold uppercase tracking-widest text-olive-600">Auto-monitor</h4>
                    <p class="mt-1 text-sm text-olive-700">Run Complete + PDF automatically for this customer.</p>
                </div>
                <label class="flex items-center gap-2 text-sm font-medium text-olive-900">
                    <input type="checkbox" class="customer-auto-monitor-enabled size-4 rounded border-olive-300 text-olive-700 focus:ring-olive-500" ${autoMonitorRule.enabled ? 'checked' : ''}>
                    Enabled
                </label>
            </div>
            <div class="mt-4 grid gap-3 md:grid-cols-2">
                <label class="text-sm text-olive-700">
                    <span class="mb-1 block font-medium text-olive-900">Recurrence</span>
                    <select class="customer-auto-monitor-recurrence form-control form-control-sm">
                        <option value="daily" ${autoMonitorRule.recurrence === 'daily' ? 'selected' : ''}>Daily</option>
                        <option value="weekly" ${autoMonitorRule.recurrence === 'weekly' ? 'selected' : ''}>Weekly</option>
                        <option value="biweekly" ${autoMonitorRule.recurrence === 'biweekly' ? 'selected' : ''}>Bi-weekly</option>
                        <option value="monthly" ${autoMonitorRule.recurrence === 'monthly' ? 'selected' : ''}>Monthly</option>
                        <option value="quarterly" ${autoMonitorRule.recurrence === 'quarterly' ? 'selected' : ''}>Quarterly</option>
                    </select>
                </label>
                <label class="text-sm text-olive-700">
                    <span class="mb-1 block font-medium text-olive-900">Time</span>
                    <input type="time" class="customer-auto-monitor-time form-control form-control-sm" value="${autoMonitorRule.time || '01:00'}">
                </label>
                <label class="text-sm text-olive-700">
                    <span class="mb-1 block font-medium text-olive-900">Weekday Anchor</span>
                    <select class="customer-auto-monitor-day form-control form-control-sm">
                        <option value="monday" ${autoMonitorRule.day_of_week === 'monday' ? 'selected' : ''}>Monday</option>
                        <option value="tuesday" ${autoMonitorRule.day_of_week === 'tuesday' ? 'selected' : ''}>Tuesday</option>
                        <option value="wednesday" ${autoMonitorRule.day_of_week === 'wednesday' ? 'selected' : ''}>Wednesday</option>
                        <option value="thursday" ${autoMonitorRule.day_of_week === 'thursday' ? 'selected' : ''}>Thursday</option>
                        <option value="friday" ${autoMonitorRule.day_of_week === 'friday' ? 'selected' : ''}>Friday</option>
                        <option value="saturday" ${autoMonitorRule.day_of_week === 'saturday' ? 'selected' : ''}>Saturday</option>
                        <option value="sunday" ${autoMonitorRule.day_of_week === 'sunday' ? 'selected' : ''}>Sunday</option>
                    </select>
                </label>
                <label class="text-sm text-olive-700">
                    <span class="mb-1 block font-medium text-olive-900">Target</span>
                    <input type="text" class="customer-auto-monitor-target form-control form-control-sm" value="${autoMonitorRule.target || ''}" placeholder="192.168.10.0/24">
                </label>
            </div>
            <div class="mt-3 text-xs text-olive-600 customer-auto-monitor-next-run">
                ${autoMonitorRule.next_run ? `Next run ${new Date(autoMonitorRule.next_run).toLocaleString()}` : 'No scheduled run yet'}
            </div>
        `;
        card.appendChild(autoMonitor);

        const actions = document.createElement('div');
        actions.className = 'mt-4 flex flex-wrap gap-2';

        const assignButton = document.createElement('button');
        assignButton.type = 'button';
        assignButton.className = 'action-button action-button-primary action-button-compact';
        assignButton.textContent = 'Assign';
        assignButton.addEventListener('click', () => {
            if (window.socket) {
                window.socket.emit('assign_customer', {
                    customer_id: customer.id,
                    customer_name: customer.name,
                });
            }
        });
        actions.appendChild(assignButton);

        const editButton = document.createElement('button');
        editButton.type = 'button';
        editButton.className = 'action-button action-button-secondary action-button-compact';
        editButton.textContent = 'Edit';
        editButton.addEventListener('click', () => editCustomer(customer));
        actions.appendChild(editButton);

        const deleteButton = document.createElement('button');
        deleteButton.type = 'button';
        deleteButton.className = 'action-button action-button-secondary action-button-compact';
        deleteButton.textContent = 'Delete';
        deleteButton.addEventListener('click', () => {
            if (window.socket) {
                window.socket.emit('delete_customer', { customer_id: customer.id });
            }
        });
        actions.appendChild(deleteButton);

        const saveMonitorButton = document.createElement('button');
        saveMonitorButton.type = 'button';
        saveMonitorButton.className = 'action-button action-button-primary action-button-compact';
        saveMonitorButton.textContent = 'Save Auto-monitor';
        saveMonitorButton.addEventListener('click', async () => {
            const updates = {
                enabled: autoMonitor.querySelector('.customer-auto-monitor-enabled')?.checked || false,
                recurrence: autoMonitor.querySelector('.customer-auto-monitor-recurrence')?.value || 'weekly',
                day_of_week: autoMonitor.querySelector('.customer-auto-monitor-day')?.value || 'sunday',
                time: autoMonitor.querySelector('.customer-auto-monitor-time')?.value || '01:00',
                target: autoMonitor.querySelector('.customer-auto-monitor-target')?.value || '',
            };

            try {
                setCustomerTabStatus(`Saving auto-monitor rule for ${customer.name}...`);
                await saveAutoMonitorRule(customer, updates);
                await loadAutoMonitorSettings();
                renderCustomersTab(customers);
                setCustomerTabStatus(`Saved auto-monitor rule for ${customer.name}.`);
            } catch (error) {
                setCustomerTabStatus(`Failed to save auto-monitor rule: ${error.message}`, true);
            }
        });
        actions.appendChild(saveMonitorButton);

        card.appendChild(actions);
        list.appendChild(card);
    });
}

function loadCustomersTab(force = false) {
    if (customersTabLoaded && !force) {
        return;
    }
    setCustomerTabStatus('Loading customers...');
    Promise.resolve()
        .then(() => loadAutoMonitorSettings())
        .catch(() => {
            customerAutoMonitorState = { defaults: null, rules: [] };
        })
        .finally(() => {
            if (window.socket) {
                window.socket.emit('get_customers');
            }
        });
}

function initializeCustomerUI(socket) {
    window.socket = window.socket || socket;
    socket.on('customer_added', data => {
        if (data.success) {
            showCustomerMessage(data.message, 'success');
            socket.emit('get_customers');
            if (typeof window.loadReportsTab === 'function') {
                window.loadReportsTab(true);
            }
        } else {
            showCustomerMessage('Failed to add customer', 'error');
        }
    });

    socket.on('customer_updated', data => {
        if (data.success) {
            showCustomerMessage(data.message, 'success');
            socket.emit('get_customers');
            if (typeof window.loadReportsTab === 'function') {
                window.loadReportsTab(true);
            }
            if (typeof window.loadHistoryTab === 'function') {
                window.loadHistoryTab(true);
            }
        } else {
            showCustomerMessage('Failed to update customer', 'error');
        }
    });

    socket.on('customer_assigned', data => {
        if (data.success) {
            showCustomerMessage(data.message, 'success');
            updateDropdownSelection(data.customer.id, data.customer.name);
        } else {
            showCustomerMessage('Failed to assign customer', 'error');
        }
    });

    socket.on('customer_identified', data => {
        console.log('Customer identified:', data);
        if (data.customer && data.customer.id) {
            window.currentMatchedCustomerId = String(data.customer.id);
            updateDropdownSelection(data.customer.id, data.customer.name);

            if (data.customer.confidence !== undefined) {
                console.log(`Customer detected with ${(data.customer.confidence * 100).toFixed(0)}% confidence via ${data.match_method}`);
            }

            if (data.customer.id !== 'unknown') {
                socket.emit('check_resumable_scan', {
                    customer_id: data.customer.id,
                    max_days: 7,
                });
            }
        }
    });

    socket.on('customer_deleted', data => {
        if (data.success) {
            showCustomerMessage(data.message, 'success');
            socket.emit('get_customers');
            if (typeof window.loadReportsTab === 'function') {
                window.loadReportsTab(true);
            }
        } else {
            showCustomerMessage('Failed to delete customer', 'error');
        }
    });

    socket.on('customer_error', message => {
        showCustomerMessage(message, 'error');
        setCustomerTabStatus(message, true);
    });

    socket.on('customers_list', data => {
        const customers = Array.isArray(data) ? data : [];
        populateCustomerDropdown(customers);
        renderCustomersTab(customers);
        customersTabLoaded = true;
    });

    document.getElementById('refresh-customers-tab-btn')?.addEventListener('click', () => {
        customersTabLoaded = false;
        loadCustomersTab(true);
    });
    document.getElementById('add-customer-tab-btn')?.addEventListener('click', showCustomerForm);
}

window.showCustomerForm = showCustomerForm;
window.hideCustomerForm = hideCustomerForm;
window.showCustomerMessage = showCustomerMessage;
window.populateCustomerDropdown = populateCustomerDropdown;
window.updateDropdownSelection = updateDropdownSelection;
window.updateCustomerSelection = updateCustomerSelection;
window.displayCustomerList = displayCustomerList;
window.initializeCustomerUI = initializeCustomerUI;
window.loadCustomersTab = loadCustomersTab;
window.renderCustomersTab = renderCustomersTab;
window.addCustomer = () => {
    if (window.socket) {
        addCustomer(window.socket);
    }
};
window.assignCustomer = () => {
    if (window.socket) {
        assignCustomer(window.socket);
    }
};
window.showCustomerList = () => {
    if (window.socket) {
        showCustomerList(window.socket);
    }
};
