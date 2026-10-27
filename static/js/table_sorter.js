class TableSorter {
    constructor(tableId) {
        this.table = document.getElementById(tableId);
        this.columnOrderStorageKey = `${tableId}ColumnOrder`;
        this.draggedColumn = null;
        this.currentSort = {
            column: null,
            direction: "asc",
        };

        this.sortFunctions = {
            ip: (a, b) => this.sortIPAddresses(a, b),
            mac: (a, b) => this.sortMACAddresses(a, b),
            text: (a, b) => this.sortText(a, b),
            number: (a, b) => this.sortNumbers(a, b),
            ports: (a, b) => this.sortPortCount(a, b),
        };

        if (!this.table) {
            console.warn(`Table with id '${tableId}' not found`);
            return;
        }

        this.initializeSorting();
        this.initializeColumnReordering();
        this.loadColumnOrder();
        this.loadSortState();
    }

    initializeSorting() {
        const headers = this.table.querySelectorAll(".sortable");
        headers.forEach((header) => {
            header.addEventListener("click", () => this.sortByColumn(header));
            header.addEventListener("keydown", (event) => {
                if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    this.sortByColumn(header);
                }
            });
            header.setAttribute("tabindex", "0");
        });
    }

    initializeColumnReordering() {
        this.getReorderableHeaders().forEach((header) => {
            header.draggable = true;
            header.classList.add("draggable-column");

            header.addEventListener("dragstart", (event) => {
                this.draggedColumn = header.dataset.column;
                header.classList.add("dragging-column");
                if (event.dataTransfer) {
                    event.dataTransfer.effectAllowed = "move";
                    event.dataTransfer.setData("text/plain", this.draggedColumn);
                }
            });

            header.addEventListener("dragover", (event) => {
                event.preventDefault();
                header.classList.add("drag-target-column");
            });

            header.addEventListener("dragleave", () => {
                header.classList.remove("drag-target-column");
            });

            header.addEventListener("drop", (event) => {
                event.preventDefault();
                header.classList.remove("drag-target-column");
                const sourceColumn = this.draggedColumn || event.dataTransfer?.getData("text/plain");
                const targetColumn = header.dataset.column;
                if (!sourceColumn || !targetColumn || sourceColumn === targetColumn) {
                    return;
                }
                this.moveColumn(sourceColumn, targetColumn);
            });

            header.addEventListener("dragend", () => {
                this.draggedColumn = null;
                this.table.querySelectorAll(".drag-target-column, .dragging-column").forEach((element) => {
                    element.classList.remove("drag-target-column", "dragging-column");
                });
            });
        });
    }

    getReorderableHeaders() {
        return Array.from(this.table.querySelectorAll('thead th[data-column]:not([data-fixed="true"])'));
    }

    getCurrentColumnOrder() {
        return this.getReorderableHeaders().map((header) => header.dataset.column);
    }

    loadColumnOrder() {
        try {
            const savedOrder = JSON.parse(localStorage.getItem(this.columnOrderStorageKey));
            if (!Array.isArray(savedOrder) || !savedOrder.length) {
                return;
            }
            this.applyColumnOrder(savedOrder);
        } catch (error) {
            console.warn("Failed to load column order:", error);
        }
    }

    saveColumnOrder() {
        localStorage.setItem(
            this.columnOrderStorageKey,
            JSON.stringify(this.getCurrentColumnOrder())
        );
    }

    applyColumnOrder(order) {
        const tableHeadRow = this.table.querySelector("thead tr");
        const tbody = this.table.querySelector("tbody");
        if (!tableHeadRow || !tbody) {
            return;
        }

        const headersByColumn = new Map(
            this.getReorderableHeaders().map((header) => [header.dataset.column, header])
        );
        const orderedHeaders = order
            .map((column) => headersByColumn.get(column))
            .filter(Boolean);
        const remainingHeaders = this.getReorderableHeaders().filter(
            (header) => !order.includes(header.dataset.column)
        );

        const statusHeader = tableHeadRow.querySelector('th[data-column="status"]');
        const actionsHeader = tableHeadRow.querySelector('th[data-column="actions"]');

        if (statusHeader) {
            tableHeadRow.appendChild(statusHeader);
        }
        orderedHeaders.concat(remainingHeaders).forEach((header) => tableHeadRow.appendChild(header));
        if (actionsHeader) {
            tableHeadRow.appendChild(actionsHeader);
        }

        Array.from(tbody.rows).forEach((row) => {
            this.reorderRowCells(row, orderedHeaders.concat(remainingHeaders).map((header) => header.dataset.column));
        });
    }

    reorderRowCells(row, orderedColumns) {
        const statusCell = row.querySelector('td[data-column="status"]');
        const actionCell = row.querySelector('td[data-column="actions"]');
        const cellsByColumn = new Map(
            Array.from(row.cells)
                .filter((cell) => cell.dataset.column && cell.dataset.column !== "status" && cell.dataset.column !== "actions")
                .map((cell) => [cell.dataset.column, cell])
        );

        if (statusCell) {
            row.appendChild(statusCell);
        }
        orderedColumns.forEach((column) => {
            const cell = cellsByColumn.get(column);
            if (cell) {
                row.appendChild(cell);
            }
        });
        if (actionCell) {
            row.appendChild(actionCell);
        }
    }

    moveColumn(sourceColumn, targetColumn) {
        const order = this.getCurrentColumnOrder();
        const sourceIndex = order.indexOf(sourceColumn);
        const targetIndex = order.indexOf(targetColumn);
        if (sourceIndex === -1 || targetIndex === -1) {
            return;
        }

        order.splice(targetIndex, 0, order.splice(sourceIndex, 1)[0]);
        this.applyColumnOrder(order);
        this.saveColumnOrder();
        this.resort();
    }

    sortByColumn(header) {
        const column = header.dataset.column;
        const type = header.dataset.type;

        if (this.currentSort.column === column) {
            this.currentSort.direction =
                this.currentSort.direction === "asc" ? "desc" : "asc";
        } else {
            this.currentSort.column = column;
            this.currentSort.direction = "asc";
        }

        this.sortTable(column, type, this.currentSort.direction);
        this.updateVisualIndicators(header);
        this.saveSortState();
    }

    sortTable(column, type, direction) {
        const tbody = this.table.querySelector("tbody");
        const rows = Array.from(tbody.querySelectorAll("tr"));

        rows.sort((a, b) => {
            const aValue = this.getCellValue(a, column);
            const bValue = this.getCellValue(b, column);
            const sortFn = this.sortFunctions[type] || this.sortFunctions.text;
            const result = sortFn(aValue, bValue);
            return direction === "asc" ? result : -result;
        });

        rows.forEach((row) => tbody.appendChild(row));
    }

    sortIPAddresses(a, b) {
        const aParts = a.split(".").map(Number);
        const bParts = b.split(".").map(Number);

        for (let index = 0; index < 4; index += 1) {
            if (aParts[index] !== bParts[index]) {
                return aParts[index] - bParts[index];
            }
        }
        return 0;
    }

    sortMACAddresses(a, b) {
        const aHex = a.replace(/:/g, "");
        const bHex = b.replace(/:/g, "");
        return parseInt(aHex, 16) - parseInt(bHex, 16);
    }

    sortText(a, b) {
        return a.localeCompare(b, undefined, {
            numeric: true,
            sensitivity: "base",
        });
    }

    sortNumbers(a, b) {
        return parseFloat(a) - parseFloat(b);
    }

    sortPortCount(a, b) {
        const aCount = (a || "").split(",").length;
        const bCount = (b || "").split(",").length;
        return aCount - bCount;
    }

    getCellValue(row, column) {
        const columnIndex = this.getColumnIndex(column);
        const cell = row.cells[columnIndex];
        return cell ? cell.textContent.trim() : "";
    }

    getColumnIndex(column) {
        const headers = Array.from(this.table.querySelectorAll("thead th"));
        const index = headers.findIndex((header) => header.dataset.column === column);
        return index === -1 ? 0 : index;
    }

    getCellByColumn(row, column) {
        const columnIndex = this.getColumnIndex(column);
        return row.cells[columnIndex] || null;
    }

    updateVisualIndicators(activeHeader) {
        this.table.querySelectorAll(".sortable").forEach((header) => {
            header.classList.remove("sorted-asc", "sorted-desc");
            header.removeAttribute("aria-sort");
        });

        const directionClass =
            this.currentSort.direction === "asc" ? "sorted-asc" : "sorted-desc";
        activeHeader.classList.add(directionClass);
        activeHeader.setAttribute(
            "aria-sort",
            this.currentSort.direction === "asc" ? "ascending" : "descending"
        );
    }

    saveSortState() {
        const state = {
            column: this.currentSort.column,
            direction: this.currentSort.direction,
            timestamp: Date.now(),
        };
        localStorage.setItem("tableSortState", JSON.stringify(state));
    }

    loadSortState() {
        try {
            const state = JSON.parse(localStorage.getItem("tableSortState"));
            if (state && state.column) {
                this.currentSort = state;
                const header = this.table.querySelector(
                    `[data-column="${state.column}"]`
                );
                if (header) {
                    this.sortTable(state.column, header.dataset.type, state.direction);
                    this.updateVisualIndicators(header);
                }
            }
        } catch (error) {
            console.warn("Failed to load sort state:", error);
        }
    }

    resort() {
        this.applyColumnOrder(this.getCurrentColumnOrder());
        if (this.currentSort.column) {
            const header = this.table.querySelector(
                `[data-column="${this.currentSort.column}"]`
            );
            if (header) {
                this.sortTable(
                    this.currentSort.column,
                    header.dataset.type,
                    this.currentSort.direction
                );
            }
        }
    }
}

window.TableSorter = TableSorter;
