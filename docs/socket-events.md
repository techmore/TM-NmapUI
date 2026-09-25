# Socket.IO Event Reference

This document reflects the current runtime contract implemented by the handler
modules in [`nmapui/handlers`](../nmapui/handlers). It is pinned by regression tests
in [`tests/test_runtime_contract.py`](../tests/test_runtime_contract.py).

Direction key:
- `C -> S` client emits to the server
- `S -> C` server emits to the browser

## Connection and auth

| Event | Direction | Payload |
|---|---|---|
| `connect` | `C -> S` | none |
| `disconnect` | `C -> S` | none |
| `auth_error` | `S -> C` | `{ error: string }` |
| `client_state_snapshot` | `S -> C` | `{ last_scan_target?: string }` |

Notes:
- New tabs receive `customer_info`, `network_key`, `client_state_snapshot`, and `auto_scan_status` during `connect`.
- If a scan or report job is already active, the new tab also receives replayed job events plus `job_status`.

## Network and runtime info

| Event | Direction | Payload |
|---|---|---|
| `get_local_ip` | `C -> S` | none |
| `local_ip` | `S -> C` | `{ local_ip, subnet_mask, public_ip, cidr, interface }` |
| `get_network_key` | `C -> S` | none |
| `network_key` | `S -> C` | `{ hops, exit_ip, public_ip, private_hops, public_hops, raw, total_hops }` |
| `get_history_counts` | `C -> S` | none |
| `history_counts` | `S -> C` | direct count document, for example `{ total, last_scans, "<customer_name>": number }` |
| `get_versions` | `C -> S` | none |
| `versions` | `S -> C` | tool/application version document |

## Customer and history operations

| Event | Direction | Payload |
|---|---|---|
| `get_customer_info` | `C -> S` | none |
| `customer_info` | `S -> C` | current customer snapshot `{ id, name, confidence, metadata?, manual_assignment? }` |
| `get_customers` | `C -> S` | none |
| `customers_list` | `S -> C` | `Customer[]` |
| `add_customer` | `C -> S` | customer form payload |
| `customer_added` | `S -> C` | `{ success, customer, message }` |
| `assign_customer` | `C -> S` | `{ customer_id, customer_name? }` |
| `customer_assigned` | `S -> C` | `{ success, customer, message }` |
| `delete_customer` | `C -> S` | `{ customer_id }` |
| `customer_deleted` | `S -> C` | `{ success, customer_id, message }` |
| `customer_error` | `S -> C` | error string payload |
| `get_customer_traceroutes` | `C -> S` | `{ customer_id }` |
| `customer_traceroutes` | `S -> C` | `{ customer_id, traceroutes }` |
| `search_scan_history` | `C -> S` | `{ customer_id?, limit? }` |
| `scan_history_results` | `S -> C` | scan history entry list |
| `assign_report_to_customer` | `C -> S` | `{ report_path, customer_id, label? }` |
| `report_assigned` | `S -> C` | `{ success, report_path, customer_id, customer_name, message }` |
| `add_labeled_public_ip` | `C -> S` | `{ customer_id, label, ip_address }` |
| `labeled_ip_added` | `S -> C` | `{ success, customer_id, label, ip_address, message }` |
| `file_updated` | `S -> C` | `{ file, action }` for persisted storage updates such as `data/runtime.sqlite3` |
| `get_network_statistics` | `C -> S` | none |
| `network_statistics` | `S -> C` | `{ total_scans, unique_customers, most_common_customer, average_confidence, recent_scans }` |

## Scan lifecycle

| Event | Direction | Payload |
|---|---|---|
| `start_scan` | `C -> S` | `{ target }` |
| `quick_scan_start` | `S -> C` | status string |
| `quickscan_results` | `S -> C` | `{ total_ips, hosts_up, time_taken }` |
| `quick_scan_complete` | `S -> C` | none |
| `arp_scan_start` | `S -> C` | none |
| `arp_results` | `S -> C` | `{ [ip]: { mac, vendor } }` |
| `arp_scan_complete` | `S -> C` | none |
| `scan_results` | `S -> C` | either live host list or historical payload |
| `deep_scan_start` | `S -> C` | none |
| `deep_scan_host_start` | `S -> C` | `{ ip }` |
| `scan_raw_output` | `S -> C` | `{ target, output }` |
| `service_info` | `S -> C` | `{ target, line }` |
| `deep_scan_results` | `S -> C` | `Host[]` |
| `cve_array` | `S -> C` | `{ target, cve_array }` |
| `deep_scan_host_complete` | `S -> C` | `{ ip }` |
| `deep_scan_complete` | `S -> C` | none |
| `scan_feedback` | `S -> C` | status string |
| `scan_error` | `S -> C` | string |

Historical resume path:
- `check_resumable_scan` `C -> S` with `{ customer_id, max_days? }`
- `resumable_scan_check` `S -> C` with either `{ available: false }` or `{ available: true, scan_date, target, duration, total_hosts, total_vulnerabilities, age_days, age_seconds }`
- `resume_from_last_scan` `C -> S` with `{ customer_id, max_days? }`
- `resume_scan_error` `S -> C` with `{ error }`

## Report generation

| Event | Direction | Payload |
|---|---|---|
| `generate_report` | `C -> S` | report request payload, including `target`, `customer_name`, and optional flags such as `chunked` |
| `generate_pdf_from_saved` | `C -> S` | saved-report PDF request payload |
| `scan_complete_summary` | `S -> C` | `{ duration_formatted, hosts_up, total_ports, total_cves, target }` |
| `report_complete` | `S -> C` | `{ status, path, scan_dir, pdf_path?, xml_path?, html_path?, diff_summary? }` |
| `report_error` | `S -> C` | `{ error }` |

## Job status

| Event | Direction | Payload |
|---|---|---|
| `get_job_status` | `C -> S` | none |
| `job_status` | `S -> C` | `{ job_type, status, started_at?, details? }` |
| `job_progress` | `S -> C` | `{ job_type, phase, message, progress, details? }` |
| `cancel_job` | `C -> S` | `{ job_type: "scan" | "report" }` |
| `job_cancelled` | `S -> C` | `{ job_type, message }` |

## Auto-scan and idle/update state

| Event | Direction | Payload |
|---|---|---|
| `update_auto_scan` | `C -> S` | schedule/settings payload |
| `auto_scan_status` | `S -> C` | current auto-scan configuration document |
| `auto_scan_error` | `S -> C` | `{ error }` |
| `check_app_updates` | `C -> S` | none |
| `app_update_available` | `S -> C` | update info document, or `{ available: false }` |
| `perform_app_update` | `C -> S` | none |
| `update_status` | `S -> C` | `{ message }` |
| `update_complete` | `S -> C` | `{ message }` |
| `update_error` | `S -> C` | `{ message }` |
| `show_auto_update_banner` | `S -> C` | update info document |
| `hide_auto_update_banner` | `S -> C` | none |
| `start_auto_update_countdown` | `C -> S` | none |
| `cancel_auto_update` | `C -> S` | none |
| `idle_state_changed` | `S -> C` | `{ idle }` |

## Type notes

- `Customer` is the runtime customer document used by the app configuration and
  assignment flows.
- `Host[]` in scan events is the normalized frontend host list used by
  [`static/js/discovery_ui.js`](../static/js/discovery_ui.js).
- `scan_results` is intentionally overloaded:
  - live quick/deep scan path emits host rows directly
  - resume path emits `{ hosts, total, is_historical, ... }`
