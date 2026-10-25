let historyLoadGeneration = 0;
let historyHasLoaded = false;

function renderHistoryState(message, isError = false) {
    const historyList = document.getElementById("history-list");
    historyList.replaceChildren();
    const paragraph = document.createElement("p");
    paragraph.className = isError ? "text-red-600" : "text-olive-600";
    paragraph.textContent = message;
    historyList.appendChild(paragraph);
}

function renderHistoryLoadError() {
    const historyList = document.getElementById("history-list");
    document.getElementById("history-load-error")?.remove();
    if (!historyHasLoaded) historyList.replaceChildren();
    const notice = document.createElement("div");
    notice.id = "history-load-error";
    notice.className = "rounded-lg border border-red-200 bg-red-50 p-3 text-red-700";
    notice.setAttribute("role", "alert");
    const message = document.createElement("p");
    message.textContent = historyHasLoaded
        ? "Could not refresh saved scan history. Previously loaded history may be out of date."
        : "Could not load saved scan history.";
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "mt-2 action-button action-button-secondary action-button-compact";
    retry.textContent = "Retry saved history";
    retry.addEventListener("click", () => loadScanHistory());
    notice.append(message, retry);
    historyList.prepend(notice);
}

function createHistoryDiffSummary(diffSummary) {
    if (!diffSummary || !diffSummary.has_changes) {
        return null;
    }

    const diffCard = document.createElement("div");
    diffCard.className =
        "mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900";

    const diffTitle = document.createElement("p");
    diffTitle.className = "font-semibold text-amber-900";
    diffTitle.textContent = "Changes since previous scan";
    diffCard.appendChild(diffTitle);

    const diffMeta = document.createElement("p");
    diffMeta.className = "mt-1 text-xs text-amber-700";
    diffMeta.textContent = `Baseline: ${new Date(diffSummary.baseline_timestamp).toLocaleString()}`;
    diffCard.appendChild(diffMeta);

    const diffFacts = [];
    if (diffSummary.added_hosts?.length) {
        diffFacts.push(`${diffSummary.added_hosts.length} new host(s)`);
    }
    if (diffSummary.removed_hosts?.length) {
        diffFacts.push(`${diffSummary.removed_hosts.length} removed host(s)`);
    }
    if (diffSummary.changed_hosts?.length) {
        diffFacts.push(`${diffSummary.changed_hosts.length} changed host(s)`);
    }
    if (diffSummary.new_ports?.length) {
        diffFacts.push(`${diffSummary.new_ports.length} new port(s)`);
    }
    if (diffSummary.removed_ports?.length) {
        diffFacts.push(`${diffSummary.removed_ports.length} removed port(s)`);
    }
    if (diffSummary.new_vulnerabilities?.length) {
        diffFacts.push(
            `${diffSummary.new_vulnerabilities.length} new vulnerabilit${diffSummary.new_vulnerabilities.length === 1 ? "y" : "ies"}`
        );
    }
    if (diffSummary.removed_vulnerabilities?.length) {
        diffFacts.push(
            `${diffSummary.removed_vulnerabilities.length} resolved vulnerabilit${diffSummary.removed_vulnerabilities.length === 1 ? "y" : "ies"}`
        );
    }

    const diffList = document.createElement("p");
    diffList.className = "mt-2 text-sm text-amber-800";
    diffList.textContent = diffFacts.join(" • ");
    diffCard.appendChild(diffList);

    return diffCard;
}

function renderHistoryList(scans) {
    const historyList = document.getElementById("history-list");
    historyList.replaceChildren();

    scans.forEach((scan) => {
        const card = document.createElement("div");
        card.className = "bg-olive-50 p-4 rounded-lg border border-olive-300";

        const header = document.createElement("div");
        header.className = "flex justify-between items-start mb-2";

        const details = document.createElement("div");
        details.className = "flex-1 min-w-0";

        const title = document.createElement("h3");
        title.className = "font-display text-lg text-olive-900";
        title.textContent = scan.customer_name || "Unknown";
        details.appendChild(title);

        const dateText = document.createElement("p");
        dateText.className = "text-sm text-olive-600";
        dateText.textContent = new Date(scan.timestamp).toLocaleString();
        details.appendChild(dateText);

        const targetText = document.createElement("p");
        targetText.className = "text-sm text-olive-700 mt-1";
        targetText.appendChild(document.createTextNode("Target: "));
        const targetSpan = document.createElement("span");
        targetSpan.className = "font-mono";
        targetSpan.textContent = scan.target;
        targetText.appendChild(targetSpan);
        details.appendChild(targetText);

        const diffCard = createHistoryDiffSummary(scan.diff_summary);
        if (diffCard) {
            details.appendChild(diffCard);
        }
        header.appendChild(details);

        const actions = document.createElement("div");
        actions.className = "flex gap-2";

        const buildLink = (href, label, className, newTab = false) => {
            const link = document.createElement("a");
            link.href = href;
            if (newTab) {
                link.target = "_blank";
                link.rel = "noopener noreferrer";
            }
            link.className = className;
            link.textContent = label;
            actions.appendChild(link);
        };

        if (scan.has_html) {
            buildLink(
                `/api/runtime/reports/${scan.path}/html`,
                "View HTML",
                "px-3 py-1 bg-olive-600 text-white rounded text-sm hover:bg-olive-700",
                true
            );
        }
        if (scan.has_pdf) {
            buildLink(
                `/api/runtime/reports/${scan.path}/pdf`,
                "Download PDF",
                "px-3 py-1 bg-olive-700 text-white rounded text-sm hover:bg-olive-800"
            );
        }
        if (scan.has_xml) {
            buildLink(
                `/api/runtime/reports/${scan.path}/xml`,
                "Download XML",
                "px-3 py-1 bg-olive-500 text-white rounded text-sm hover:bg-olive-600"
            );
        }

        const deleteButton = document.createElement("button");
        deleteButton.className =
            "px-3 py-1 bg-red-600 text-white rounded text-sm hover:bg-red-700";
        deleteButton.textContent = "Delete";
        deleteButton.addEventListener("click", () => window.deleteScan(scan.path));
        actions.appendChild(deleteButton);

        header.appendChild(actions);
        card.appendChild(header);
        historyList.appendChild(card);
    });
}

function populateCustomerFilter(scans, defaultValue = "") {
    const filter = document.getElementById("history-customer-filter");
    const customers = [...new Set(scans.map((scan) => scan.customer_name))].sort();
    const currentValue = filter.value || defaultValue;

    filter.replaceChildren();
    const defaultOption = document.createElement("option");
    defaultOption.value = "";
    defaultOption.textContent = "All Customers";
    filter.appendChild(defaultOption);

    customers.forEach((customer) => {
        const option = document.createElement("option");
        option.value = customer;
        option.textContent = customer;
        filter.appendChild(option);
    });

    if (customers.includes(currentValue)) {
        filter.value = currentValue;
    } else {
        filter.value = "";
    }
}

function displayScanHistory(scans) {
    if (scans.length === 0) {
        renderHistoryState("No scans found");
        return;
    }

    renderHistoryList(scans);
}

async function loadScanHistory(isInitialLoad = false) {
    const generation = ++historyLoadGeneration;
    const modal = document.getElementById("history-modal");
    const filter = document.getElementById("history-customer-filter");
    const dateFilter = document.getElementById("history-date-filter").value;
    const changedOnly = document.getElementById("history-changed-filter").checked;

    let customerFilter = filter.value;
    if (isInitialLoad && !customerFilter && modal.dataset.defaultCustomer) {
        customerFilter = modal.dataset.defaultCustomer;
    }

    try {
        const response = await fetch("/api/runtime/history");
        if (!response.ok) throw new Error(`History request failed (${response.status})`);
        const data = await response.json();
        if (!Array.isArray(data.history) || data.history.some(scan => !scan || typeof scan !== "object" || Array.isArray(scan))) {
            throw new Error("Invalid saved history response");
        }
        // Filter changes can overlap. Only the newest read may replace the
        // list or report an error; a slow earlier response is stale evidence.
        if (generation !== historyLoadGeneration) return;

        let scans = data.history;
        populateCustomerFilter(scans, customerFilter);

        const activeFilter = filter.value;
        if (activeFilter) {
            scans = scans.filter((scan) => scan.customer_name === activeFilter);
        }
        if (dateFilter) {
            scans = scans.filter((scan) => scan.date === dateFilter);
        }
        if (changedOnly) {
            scans = scans.filter((scan) => scan.diff_summary?.has_changes);
        }

        displayScanHistory(scans);
        historyHasLoaded = true;
    } catch (error) {
        if (generation !== historyLoadGeneration) return;
        console.error("Error loading scan history:", error);
        renderHistoryLoadError();
    }
}

function showHistoryModal() {
    const modal = document.getElementById("history-modal");
    const customerDropdown = document.getElementById("current-customer");

    modal.classList.remove("hidden");

    let currentName = "";
    if (customerDropdown && customerDropdown.selectedOptions[0]) {
        currentName = customerDropdown.selectedOptions[0].text.split(" (")[0];
    }

    if (
        currentName &&
        currentName !== "Unassigned" &&
        currentName !== "Unknown Network" &&
        currentName !== "Auto-detect network..."
    ) {
        modal.dataset.defaultCustomer = currentName;
    } else {
        delete modal.dataset.defaultCustomer;
    }

    loadScanHistory(true);
}

function hideHistoryModal() {
    ++historyLoadGeneration;
    document.getElementById("history-modal").classList.add("hidden");
}

window.renderHistoryState = renderHistoryState;
window.createHistoryDiffSummary = createHistoryDiffSummary;
window.renderHistoryList = renderHistoryList;
window.populateCustomerFilter = populateCustomerFilter;
window.displayScanHistory = displayScanHistory;
window.loadScanHistory = loadScanHistory;
window.showHistoryModal = showHistoryModal;
window.hideHistoryModal = hideHistoryModal;
