import json
import logging
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path

import yaml

from customer_fingerprint_matcher import CustomerFingerprintMatcher
from customer_fingerprint_store import (
    CustomerFingerprintStore,
    ScanHistoryStore,
    backfill_runtime_customer_scan_history,
)
from nmapui.paths import CUSTOMER_CONFIG_FILE, CUSTOMER_TRACEROUTES_FILE, DATA_DIR

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

class CustomerFingerprinter:
    def __init__(self, config_path: Optional[str] = None, runtime_store=None):
        self.config_path = config_path or CUSTOMER_CONFIG_FILE
        self.config = None
        self.customers = []
        self.unknown_customer = None
        self.settings = {}
        self.traceroutes_path = CUSTOMER_TRACEROUTES_FILE
        self.customer_traceroutes = {}
        self.last_match_method = "unknown"
        self.runtime_store = runtime_store
        self.store = CustomerFingerprintStore(
            config_path=self.config_path,
            traceroutes_path=self.traceroutes_path,
            logger=logger,
        )
        self.scan_history_store = ScanHistoryStore(logger=logger)
        self.matcher = CustomerFingerprintMatcher(logger=logger)
        self.load_config()
        self.load_traceroute_history()

    def set_runtime_store(self, runtime_store) -> None:
        self.runtime_store = runtime_store

    def backfill_runtime_scan_history(self) -> int:
        return backfill_runtime_customer_scan_history(
            runtime_store=self.runtime_store,
            scan_history_path=self._scan_history_path(),
            logger=logger,
        )

    def _scan_history_path(self) -> Path:
        configured = (self.config or {}).get("indexing", {}).get(
            "storage_path", "data/scan_history.json"
        )
        path = Path(str(configured or "data/scan_history.json")).expanduser()
        if path.is_absolute():
            return path
        if path.parts and path.parts[0] == "data":
            path = Path(*path.parts[1:])
        return DATA_DIR / path

    def load_config(self):
        try:
            self.store.config_path = Path(self.config_path)
            self.config = self.store.load_config_document()

            self.settings = self.config.get("settings", {})
            self.customers = self.config.get("customers", [])
            unknown = self.config.get("unknown_customer", {})
            self.unknown_customer = unknown if unknown is not None else {}

            logger.info(f"Loaded {len(self.customers)} customer configurations")

        except FileNotFoundError:
            logger.warning(f"Customer config file not found at {self.config_path}")
            self.config = {}
            self.settings = {}
            self.customers = []
            self.unknown_customer = {}
        except yaml.YAMLError as e:
            logger.error(f"Error parsing customer config: {e}")
            self.config = {}
            self.settings = {}
            self.customers = []
            self.unknown_customer = {}

    def load_traceroute_history(self):
        try:
            self.store.traceroutes_path = Path(self.traceroutes_path)
            self.customer_traceroutes = self.store.load_traceroute_customers()

            total_traceroutes = sum(
                len(c.get("traceroutes", []))
                for c in self.customer_traceroutes.values()
            )
            logger.info(
                f"Loaded traceroute history: {len(self.customer_traceroutes)} customers, {total_traceroutes} total samples"
            )

        except json.JSONDecodeError as e:
            logger.error(f"Error parsing traceroute history: {e}")
            self.customer_traceroutes = {}
        except Exception as e:
            logger.error(f"Error loading traceroute history: {e}")
            self.customer_traceroutes = {}

    def save_traceroute_to_history(
        self, customer_id: Optional[str], network_key: Dict, label: Optional[str] = None
    ):
        try:
            traceroute_entry = {
                "timestamp": datetime.now().isoformat(),
                "public_ip": network_key.get("public_ip"),
                "exit_ip": network_key.get("exit_ip"),
                "hop_count": len(network_key.get("hops", [])),
                "network_signature": self.matcher.create_network_signature(network_key),
                "label": label or network_key.get("public_ip", "unknown"),
                "raw_traceroute": network_key.get("raw", ""),
            }

            customer_id = customer_id or "unknown"

            if customer_id not in self.customer_traceroutes:
                self.customer_traceroutes[customer_id] = {
                    "name": self.customer_traceroutes.get(customer_id, {}).get(
                        "name", customer_id
                    ),
                    "traceroutes": [],
                }

            traces = self.customer_traceroutes[customer_id]["traceroutes"]
            traces.append(traceroute_entry)
            # Keep only the most recent 200 traceroutes per customer
            if len(traces) > 200:
                self.customer_traceroutes[customer_id]["traceroutes"] = traces[-200:]

            self.store.traceroutes_path = Path(self.traceroutes_path)
            self.store.save_traceroute_customers(self.customer_traceroutes)

            logger.info(
                f"Saved traceroute to history for customer '{customer_id}': {network_key.get('public_ip')}"
            )

        except Exception as e:
            logger.error(f"Error saving traceroute to history: {e}")

    def _build_generated_customer_id(self, network_key: Dict) -> str:
        public_ip = str(network_key.get("public_ip") or "").strip()
        signature = self.matcher.create_network_signature(network_key)
        seed = public_ip or signature or str(network_key.get("exit_ip") or "unknown")
        digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:12]
        return f"auto-wan-{digest}"

    def _build_generated_customer_name(self, network_key: Dict) -> str:
        public_ip = str(network_key.get("public_ip") or "").strip()
        if public_ip:
            return f"WAN {public_ip}"
        exit_ip = str(network_key.get("exit_ip") or "").strip()
        if exit_ip:
            return f"WAN Exit {exit_ip}"
        return "Observed WAN"

    def ensure_generated_customer(self, network_key: Dict) -> Dict:
        public_ip = str(network_key.get("public_ip") or "").strip()
        exit_ip = str(network_key.get("exit_ip") or "").strip()
        signature = self.matcher.create_network_signature(network_key)
        customer_id = self._build_generated_customer_id(network_key)

        existing = self.get_customer_by_id(customer_id)
        if existing:
            networks = existing.setdefault("networks", {})
            public_ips = networks.setdefault("public_ips", [])
            if public_ip and public_ip not in public_ips:
                public_ips.append(public_ip)
            if public_ip and not networks.get("public_ip"):
                networks["public_ip"] = public_ip
            exit_ips = networks.get("exit_ips")
            if not isinstance(exit_ips, list):
                exit_ips = [] if exit_ip else "dynamic"
            if isinstance(exit_ips, list) and exit_ip and exit_ip not in exit_ips:
                exit_ips.append(exit_ip)
            networks["exit_ips"] = exit_ips
            metadata = existing.setdefault("metadata", {})
            metadata["auto_generated"] = True
            metadata["last_seen"] = datetime.now().isoformat()
            if signature:
                metadata["network_signature"] = signature
            self.customer_traceroutes.setdefault(
                customer_id,
                {"name": existing.get("name", customer_id), "traceroutes": []},
            )["name"] = existing.get("name", customer_id)
            self.save_customers_config()
            return existing

        customer = {
            "id": customer_id,
            "name": self._build_generated_customer_name(network_key),
            "description": "Auto-created from an observed public WAN during customer identification.",
            "confidence": 0.35,
            "networks": {
                "public_ip": public_ip or "dynamic",
                "public_ips": [public_ip] if public_ip else [],
                "private_ranges": [],
                "exit_ips": [exit_ip] if exit_ip else "dynamic",
                "gateway_pattern": "",
                "labeled_public_ips": {},
            },
            "fingerprints": [],
            "metadata": {
                "auto_generated": True,
                "generated_from_public_ip": public_ip or "",
                "generated_from_exit_ip": exit_ip or "",
                "network_signature": signature,
                "created_at": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
            },
        }
        self.customers.append(customer)
        self.customer_traceroutes.setdefault(
            customer_id, {"name": customer["name"], "traceroutes": []}
        )
        self.save_customers_config()
        logger.info(
            "Auto-created generated customer '%s' for public IP %s",
            customer["name"],
            public_ip or "unknown",
        )
        return customer

    def match_customer(self, network_key: Dict):
        matched_customer, confidence = self.matcher.match_customer(
            network_key=network_key,
            customers=self.customers,
            customer_traceroutes=self.customer_traceroutes,
            unknown_customer=self.unknown_customer,
        )
        self.last_match_method = self.matcher.last_match_method
        return matched_customer, confidence

    def save_scan_result(self, network_key: Dict, customer: Dict, confidence: float):
        if not self.config or not self.config.get("indexing", {}).get("enabled", True):
            return

        indexing_config = self.config.get("indexing", {})
        storage_path = self._scan_history_path()

        scan_result = {
            "timestamp": datetime.now().isoformat(),
            "customer_id": customer.get("id", "unknown"),
            "customer_name": customer.get("name", "Unknown"),
            "confidence_score": confidence,
            "exit_ip": network_key.get("exit_ip"),
            "hop_count": len(network_key.get("hops", [])),
            "private_hop_count": len(network_key.get("private_hops", [])),
            "public_hop_count": len(network_key.get("public_hops", [])),
            "network_signature": self.matcher.create_network_signature(network_key),
            "raw_traceroute": network_key.get("raw", ""),
            "network_key": network_key,
        }

        try:
            storage_path.parent.mkdir(parents=True, exist_ok=True)
            if self.runtime_store is not None and hasattr(self.runtime_store, "append_customer_scan_history"):
                self.runtime_store.append_customer_scan_history(
                    customer_id=scan_result.get("customer_id"),
                    payload=scan_result,
                )
            max_entries = indexing_config.get("max_entries", 500)
            self.scan_history_store.append_entry(
                storage_path,
                scan_result,
                max_entries=max_entries,
            )

            logger.info(f"Scan result saved to {storage_path}")
        except Exception as e:
            logger.error(f"Error saving scan result: {e}")

    def update_last_scan_duration(self, customer_id: str, duration_str: str):
        found = False
        for customer in self.customers:
            if customer.get("id") == customer_id:
                if "metadata" not in customer:
                    customer["metadata"] = {}
                customer["metadata"]["last_scan_duration"] = duration_str
                customer["metadata"]["last_scan_date"] = datetime.now().isoformat()
                found = True
                break

        if found:
            self.save_customers_config()
            logger.info(f"Updated last scan duration for {customer_id}: {duration_str}")
            return True

        logger.warning(f"Customer {customer_id} not found for duration update")
        return False

    def get_customer_by_id(self, customer_id: str):
        """Get customer configuration by ID"""
        for customer in self.customers:
            if customer.get("id") == customer_id:
                return customer
        return None

    def save_customers_config(self):
        try:
            config_data = {
                "version": (self.config or {}).get("version", "1.0"),
                "description": (self.config or {}).get(
                    "description", "Customer network fingerprinting database"
                ),
                "settings": self.settings,
                "customers": self.customers,
                "unknown_customer": self.unknown_customer,
                "indexing": (self.config or {}).get("indexing", {}),
            }

            self.store.config_path = Path(self.config_path)
            self.store.save_config_document(config_data)

            logger.info(f"Customers config saved to {self.config_path}")

        except Exception as e:
            logger.error(f"Error saving customers config: {e}")

    def get_scan_history(
        self, customer_id: Optional[str] = None, limit: int = 50
    ) -> List[Dict]:
        runtime_history = self._get_runtime_scan_history(customer_id=customer_id, limit=limit)
        if runtime_history:
            return runtime_history

        storage_path = self._scan_history_path()

        if not storage_path.exists():
            return []

        return self.scan_history_store.get_entries(
            storage_path,
            customer_id=customer_id,
            limit=limit,
        )

    def _get_runtime_scan_history(
        self,
        *,
        customer_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict]:
        if self.runtime_store is None or not hasattr(self.runtime_store, "list_report_artifacts"):
            if self.runtime_store is None or not hasattr(self.runtime_store, "list_customer_scan_history"):
                return []

        if hasattr(self.runtime_store, "list_customer_scan_history"):
            try:
                rows = self.runtime_store.list_customer_scan_history(
                    customer_id=customer_id,
                    limit=limit,
                )
            except Exception as exc:
                logger.error(f"Error loading customer scan history from runtime store: {exc}")
                rows = []

            if rows:
                return [dict(row.get("payload", {}) or {}) for row in rows]

        try:
            artifacts = self.runtime_store.list_report_artifacts(customer_id=customer_id)
        except Exception as exc:
            logger.error(f"Error loading runtime scan history: {exc}")
            return []

        history = []
        for artifact in artifacts:
            payload = dict(artifact.get("payload", {}) or {})
            artifact_customer_id = str(
                payload.get("customer_id")
                or artifact.get("customer_id")
                or payload.get("customer_info", {}).get("id", "")
                or ""
            )
            if customer_id and artifact_customer_id != customer_id:
                continue

            history.append(
                {
                    **payload,
                    "customer_id": artifact_customer_id,
                    "customer_name": payload.get(
                        "customer_name",
                        payload.get("customer", artifact_customer_id or "Unknown"),
                    ),
                    "target": payload.get("target", artifact.get("target")),
                    "scan_path": artifact.get("scan_path", ""),
                    "has_html": bool(artifact.get("html_path")),
                    "has_pdf": bool(artifact.get("pdf_path")),
                    "has_xml": bool(artifact.get("xml_path")),
                    "source": "runtime_store",
                }
            )

        history.sort(key=lambda item: str(item.get("timestamp", "") or ""), reverse=True)
        return history[:limit]
