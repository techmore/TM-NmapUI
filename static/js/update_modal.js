function setUpdateReleaseNotes(data) {
    const notesDiv = document.getElementById("update-release-notes");
    if (!notesDiv) {
        return;
    }
    notesDiv.replaceChildren();

    const title = document.createElement("strong");
    title.textContent = "Release Notes:";
    notesDiv.appendChild(title);
    notesDiv.appendChild(document.createElement("br"));

    const lines = data.available
        ? (data.release_notes
            ? String(data.release_notes).split(/\n/)
            : [`New version ${data.latest_version} is available.`])
        : ["You are using the latest version."];

    lines.forEach((line, index) => {
        if (index > 0) {
            notesDiv.appendChild(document.createElement("br"));
        }
        notesDiv.appendChild(document.createTextNode(line));
    });
}

function appendUpdateLogLine(message, isError = false) {
    const log = document.getElementById("update-log");
    if (!log) {
        return;
    }
    const line = document.createElement("div");
    line.className = isError ? "py-0.5 text-red-400 font-bold" : "py-0.5";

    const timestamp = document.createElement("span");
    timestamp.className = "text-zinc-500 mr-2";
    timestamp.textContent = `[${new Date().toLocaleTimeString()}]`;
    line.appendChild(timestamp);
    line.appendChild(
        document.createTextNode(isError ? ` ERROR: ${message}` : ` ${message}`)
    );
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
}

function showUpdateModal() {
    const modal = document.getElementById("update-modal");
    if (!modal) {
        return;
    }
    modal.classList.remove("hidden");
}

function hideUpdateModal() {
    const modal = document.getElementById("update-modal");
    const log = document.getElementById("update-log");
    const status = document.getElementById("update-current-status");
    const progressBar = document.getElementById("update-progress-bar");
    const percentage = document.getElementById("update-percentage");

    if (modal) {
        modal.classList.add("hidden");
    }
    if (log) {
        log.innerHTML = "";
    }
    if (status) {
        status.textContent = "Ready to update";
    }
    if (progressBar) {
        progressBar.style.width = "0%";
        progressBar.classList.remove("bg-red-500");
    }
    if (percentage) {
        percentage.textContent = "0%";
    }
}

function startAppUpdate(socket) {
    appendUpdateLogLine("Opening installer download...");
    socket.emit("perform_app_update");
    const status = document.getElementById("update-current-status");
    if (status) {
        status.textContent = "Opening installer...";
    }
}

function initializeUpdateModal(socket, deps = {}) {
    const showReportStatus =
        deps.showReportStatus || window.showReportStatus || (() => {});
    const checkButton = document.getElementById("check-app-updates");
    const checkStatus = document.getElementById("update-check-status");

    if (checkButton && checkButton.dataset.bound !== "true") {
        checkButton.addEventListener("click", () => {
            checkButton.disabled = true;
            if (checkStatus) {
                checkStatus.textContent = "Checking release metadata…";
            }
            socket.emit("check_app_updates");
        });
        checkButton.dataset.bound = "true";
    }

    socket.on("app_update_available", (data) => {
        const badge = document.getElementById("app-update-badge");
        const version = document.getElementById("update-version");
        if (checkButton) {
            checkButton.disabled = false;
        }
        if (checkStatus) {
            if (data.error || data.disabled) {
                checkStatus.textContent = "Update check unavailable";
            } else if (data.available) {
                checkStatus.textContent = `Version ${data.latest_version} is available`;
            } else {
                checkStatus.textContent = `Up to date (${data.current_version || "current version"})`;
            }
        }
        if (badge && data.available) {
            badge.classList.remove("hidden");
        } else if (badge) {
            badge.classList.add("hidden");
        }
        if (version) {
            version.textContent = data.latest_version || data.current_version || "";
        }
        setUpdateReleaseNotes(data);
    });

    socket.on("update_status", (data) => {
        console.log("Update status:", data.message);
        const statusText = document.getElementById("update-current-status");
        const progressBar = document.getElementById("update-progress-bar");
        const percentageText = document.getElementById("update-percentage");

        if (statusText) {
            statusText.textContent = data.message;
        }
        appendUpdateLogLine(data.message);

        let progress = 15;
        if (data.message.includes("Opening installer")) {
            progress = 35;
        } else if (data.message.includes("Opening release")) {
            progress = 35;
        } else if (data.message.includes("Manual install required")) {
            progress = 100;
        }

        if (progressBar) {
            progressBar.style.width = `${progress}%`;
        }
        if (percentageText) {
            percentageText.textContent = `${progress}%`;
        }
    });

    socket.on("update_complete", (data) => {
        const status = document.getElementById("update-current-status");
        const progressBar = document.getElementById("update-progress-bar");
        const percentageText = document.getElementById("update-percentage");
        if (status) {
            status.textContent = data.message;
        }
        if (progressBar) {
            progressBar.style.width = "100%";
        }
        if (percentageText) {
            percentageText.textContent = "100%";
        }
        appendUpdateLogLine(data.message);
    });

    socket.on("update_error", (data) => {
        console.error("Update error:", data.message);
        if (checkButton) {
            checkButton.disabled = false;
        }
        if (checkStatus) {
            checkStatus.textContent = "Update check failed";
        }
        appendUpdateLogLine(data.message, true);
        const status = document.getElementById("update-current-status");
        const progressBar = document.getElementById("update-progress-bar");
        if (status) {
            status.textContent = "Update failed";
            status.classList.add("text-red-700");
        }
        if (progressBar) {
            progressBar.classList.add("bg-red-500");
        }
    });

    socket.on("show_auto_update_banner", (data) => {
        showReportStatus(
            `Application update available: ${data.latest_version}. Installer download will open when the countdown ends.`,
            "info"
        );
    });

    socket.on("hide_auto_update_banner", () => {
        const badge = document.getElementById("app-update-badge");
        if (badge) {
            badge.classList.add("hidden");
        }
    });
}

window.setUpdateReleaseNotes = setUpdateReleaseNotes;
window.appendUpdateLogLine = appendUpdateLogLine;
window.showUpdateModal = showUpdateModal;
window.hideUpdateModal = hideUpdateModal;
window.initializeUpdateModal = initializeUpdateModal;
window.startAppUpdate = () => {
    if (window.socket) {
        startAppUpdate(window.socket);
    }
};
