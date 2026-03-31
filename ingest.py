"""Ingestion and correlation engine.

Processes raw Zeek and Sysmon log data from Elasticsearch and builds/updates
the central NetworkMap model.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone

from elastic_client import ElasticClient
from config import Config
from models import Endpoint, NetworkMap

logger = logging.getLogger(__name__)


def _safe(doc: dict, *keys, default=None):
    """Safely traverse nested dict keys."""
    cur = doc
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k, default)
        else:
            return default
    return cur if cur is not None else default


def _is_internal(ip: str) -> bool | None:
    """Determine if an IP is RFC1918/internal. Returns None if unparseable."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return None


def _update_timestamps(obj, timestamp: str | None):
    """Update first_seen / last_seen on an object."""
    if not timestamp:
        return
    if obj.first_seen is None or timestamp < obj.first_seen:
        obj.first_seen = timestamp
    if obj.last_seen is None or timestamp > obj.last_seen:
        obj.last_seen = timestamp


def parse_time_range(spec: str) -> timedelta | None:
    """Parse a human-readable time range like '1h', '30m', '7d' into a timedelta."""
    m = re.match(r"^(\d+)\s*([mhdw])$", spec.strip().lower())
    if not m:
        return None
    val = int(m.group(1))
    unit = m.group(2)
    if unit == "m":
        return timedelta(minutes=val)
    if unit == "h":
        return timedelta(hours=val)
    if unit == "d":
        return timedelta(days=val)
    if unit == "w":
        return timedelta(weeks=val)
    return None


class IngestEngine:
    """Pulls data from Elasticsearch and updates the NetworkMap."""

    def __init__(self, es_client: ElasticClient, network_map: NetworkMap):
        self.es = es_client
        self.net_map = network_map
        self._last_timestamp: str | None = None
        # Time window: controls how far back to look on first poll / reload
        self._time_range: str = Config.DEFAULT_TIME_RANGE
        # Optional fixed upper bound (ISO string) — None means "now"
        self._time_until: str | None = None

    @property
    def time_range(self) -> str:
        return self._time_range

    @property
    def time_until(self) -> str | None:
        return self._time_until

    def set_time_range(self, time_range: str, time_until: str | None = None):
        """Set a new time window and trigger a full data reload."""
        self._time_range = time_range
        self._time_until = time_until
        self._last_timestamp = None  # Force full reload on next cycle
        # Clear the network map so stale data from old range is removed
        self.net_map.endpoints.clear()
        self.net_map.connections.clear()
        self.net_map.dns_map.clear()
        logger.info("Time range changed to %s (until=%s) — will reload on next poll", time_range, time_until or "now")

    def _compute_since(self) -> str | None:
        """Compute the 'since' timestamp for the current poll."""
        if self._last_timestamp:
            return self._last_timestamp
        # First poll: compute from time_range spec
        td = parse_time_range(self._time_range)
        if td:
            anchor = datetime.now(timezone.utc) if not self._time_until else datetime.fromisoformat(self._time_until)
            return (anchor - td).isoformat()
        return None

    def run_poll_cycle(self):
        """Execute a full poll cycle, fetching new data since last poll."""
        since = self._compute_since()
        until = self._time_until  # None means no upper bound (live)
        now = datetime.now(timezone.utc).isoformat()
        logger.info("Poll cycle started (since=%s, until=%s)", since or "beginning", until or "now")

        counts = {
            "zeek_conn": 0,
            "zeek_dns": 0,
            "zeek_ssl": 0,
            "zeek_http": 0,
            "zeek_x509": 0,
            "zeek_software": 0,
            "zeek_kerberos": 0,
            "zeek_modbus": 0,
            "zeek_dnp3": 0,
            "zeek_s7comm": 0,
            "zeek_bacnet": 0,
            "zeek_enip": 0,
            "zeek_cip": 0,
            "sysmon_net": 0,
            "sysmon_proc": 0,
            "sysmon_dns": 0,
        }

        # --- Zeek conn.log ---
        for doc in self.es.fetch_zeek_conn(since, until):
            self._process_zeek_conn(doc)
            counts["zeek_conn"] += 1

        # --- Zeek dns.log ---
        for doc in self.es.fetch_zeek_dns(since, until):
            self._process_zeek_dns(doc)
            counts["zeek_dns"] += 1

        # --- Zeek ssl.log ---
        for doc in self.es.fetch_zeek_ssl(since, until):
            self._process_zeek_ssl(doc)
            counts["zeek_ssl"] += 1

        # --- Zeek http.log ---
        for doc in self.es.fetch_zeek_http(since, until):
            self._process_zeek_http(doc)
            counts["zeek_http"] += 1

        # --- Zeek x509 ---
        for doc in self.es.fetch_zeek_x509(since, until):
            self._process_zeek_x509(doc)
            counts["zeek_x509"] += 1

        # --- Zeek software ---
        for doc in self.es.fetch_zeek_software(since, until):
            self._process_zeek_software(doc)
            counts["zeek_software"] += 1

        # --- Zeek kerberos ---
        for doc in self.es.fetch_zeek_kerberos(since, until):
            self._process_zeek_kerberos(doc)
            counts["zeek_kerberos"] += 1

        # --- Zeek ICS/OT protocols ---
        for doc in self.es.fetch_zeek_modbus(since, until):
            self._process_zeek_modbus(doc)
            counts["zeek_modbus"] += 1

        for doc in self.es.fetch_zeek_dnp3(since, until):
            self._process_zeek_dnp3(doc)
            counts["zeek_dnp3"] += 1

        for doc in self.es.fetch_zeek_s7comm(since, until):
            self._process_zeek_s7comm(doc)
            counts["zeek_s7comm"] += 1

        for doc in self.es.fetch_zeek_bacnet(since, until):
            self._process_zeek_bacnet(doc)
            counts["zeek_bacnet"] += 1

        for doc in self.es.fetch_zeek_enip(since, until):
            self._process_zeek_enip(doc)
            counts["zeek_enip"] += 1

        for doc in self.es.fetch_zeek_cip(since, until):
            self._process_zeek_cip(doc)
            counts["zeek_cip"] += 1

        # --- Sysmon network connections (Event ID 3) ---
        for doc in self.es.fetch_sysmon_network(since, until):
            self._process_sysmon_network(doc)
            counts["sysmon_net"] += 1

        # --- Sysmon process creation (Event ID 1) ---
        for doc in self.es.fetch_sysmon_process_create(since, until):
            self._process_sysmon_process(doc)
            counts["sysmon_proc"] += 1

        # --- Sysmon DNS (Event ID 22) ---
        for doc in self.es.fetch_sysmon_dns(since, until):
            self._process_sysmon_dns(doc)
            counts["sysmon_dns"] += 1

        self._last_timestamp = now
        self.net_map.last_poll_time = now
        self.net_map.version += 1

        total = sum(counts.values())
        logger.info(
            "Poll cycle complete: %d total records processed | %s",
            total,
            " | ".join(f"{k}={v}" for k, v in counts.items() if v > 0),
        )

    # ------------------------------------------------------------------
    # Zeek processors
    # ------------------------------------------------------------------

    def _process_zeek_conn(self, doc: dict):
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        src_port = _safe(doc, "source", "port")
        dst_port = _safe(doc, "destination", "port", default=0)
        proto = _safe(doc, "network", "transport", default="unknown")
        service = _safe(doc, "network", "protocol", default="")
        orig_bytes = _safe(doc, "source", "bytes", default=0) or 0
        resp_bytes = _safe(doc, "destination", "bytes", default=0) or 0
        orig_pkts = _safe(doc, "source", "packets", default=0) or 0
        resp_pkts = _safe(doc, "destination", "packets", default=0) or 0
        conn_state = _safe(doc, "zeek", "conn", "conn_state", default="")
        history = _safe(doc, "zeek", "conn", "history", default="")
        src_mac = _safe(doc, "source", "mac")
        dst_mac = _safe(doc, "destination", "mac")
        duration = _safe(doc, "event", "duration")

        if not src_ip or not dst_ip:
            return

        # Update source endpoint
        src_ep = self.net_map.get_or_create_endpoint(src_ip)
        src_ep.is_internal = _is_internal(src_ip) if src_ep.is_internal is None else src_ep.is_internal
        src_ep.protocols.add(proto)
        src_ep.connection_count += 1
        src_ep.total_bytes_sent += orig_bytes
        src_ep.total_bytes_received += resp_bytes
        if src_mac:
            src_ep.mac_addresses.add(src_mac)
        _update_timestamps(src_ep, ts)

        # Update destination endpoint
        dst_ep = self.net_map.get_or_create_endpoint(dst_ip)
        dst_ep.is_internal = _is_internal(dst_ip) if dst_ep.is_internal is None else dst_ep.is_internal
        dst_ep.protocols.add(proto)
        dst_ep.connection_count += 1
        dst_ep.total_bytes_sent += resp_bytes
        dst_ep.total_bytes_received += orig_bytes
        if dst_mac:
            dst_ep.mac_addresses.add(dst_mac)
        if dst_port:
            if dst_port not in dst_ep.open_ports:
                dst_ep.open_ports[dst_port] = set()
            dst_ep.open_ports[dst_port].add(service or proto)
        if service:
            dst_ep.services.add(service)
        _update_timestamps(dst_ep, ts)

        # Update connection
        conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, proto)
        conn.service = service or conn.service
        conn.total_bytes += orig_bytes + resp_bytes
        conn.total_packets += orig_pkts + resp_pkts
        conn.count += 1
        if conn_state:
            conn.conn_states.add(conn_state)
        if history:
            conn.history.add(history)
        _update_timestamps(conn, ts)

    def _process_zeek_dns(self, doc: dict):
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        query_name = _safe(doc, "dns", "question", "name")
        query_type = _safe(doc, "dns", "question", "type")
        answers = _safe(doc, "dns", "answers")
        resolved_ips = _safe(doc, "dns", "resolved_ip")

        if src_ip:
            ep = self.net_map.get_or_create_endpoint(src_ip)
            ep.is_internal = _is_internal(src_ip) if ep.is_internal is None else ep.is_internal
            if query_name:
                ep.dns_queries.add(query_name)
            _update_timestamps(ep, ts)

        # Map domain -> resolved IPs
        if query_name and resolved_ips:
            if isinstance(resolved_ips, str):
                resolved_ips = [resolved_ips]
            if query_name not in self.net_map.dns_map:
                self.net_map.dns_map[query_name] = set()
            for rip in resolved_ips:
                self.net_map.dns_map[query_name].add(rip)
                # Add hostname to the resolved IP endpoint
                rep = self.net_map.get_or_create_endpoint(rip)
                rep.hostnames.add(query_name)
                rep.is_internal = _is_internal(rip) if rep.is_internal is None else rep.is_internal

    def _process_zeek_ssl(self, doc: dict):
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        dst_port = _safe(doc, "destination", "port", default=0)
        server_name = _safe(doc, "tls", "client", "server_name") or _safe(doc, "zeek", "ssl", "server_name")
        ja3_hash = _safe(doc, "tls", "client", "ja3") or _safe(doc, "zeek", "ssl", "ja3")
        subject = _safe(doc, "tls", "server", "subject") or _safe(doc, "zeek", "ssl", "subject")
        issuer = _safe(doc, "tls", "server", "issuer") or _safe(doc, "zeek", "ssl", "issuer")
        version = _safe(doc, "tls", "version")

        if dst_ip:
            ep = self.net_map.get_or_create_endpoint(dst_ip)
            ep.services.add("ssl/tls")
            if server_name:
                ep.hostnames.add(server_name)
            if subject or issuer:
                ep.certificates.append({
                    "subject": subject,
                    "issuer": issuer,
                    "server_name": server_name,
                    "version": version,
                })
            _update_timestamps(ep, ts)

        if src_ip and dst_ip and dst_port:
            conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, "tcp")
            if server_name:
                conn.associated_domains.add(server_name)
            if ja3_hash:
                conn.ja3_hashes.add(ja3_hash)
            conn.service = conn.service or "ssl"

    def _process_zeek_http(self, doc: dict):
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        dst_port = _safe(doc, "destination", "port", default=0)
        host_header = _safe(doc, "url", "domain") or _safe(doc, "zeek", "http", "host")
        uri = _safe(doc, "url", "path")
        method = _safe(doc, "http", "request", "method")
        user_agent = _safe(doc, "user_agent", "original") or _safe(doc, "zeek", "http", "user_agent")
        status_code = _safe(doc, "http", "response", "status_code")
        server_header = _safe(doc, "zeek", "http", "server_header")

        if dst_ip:
            ep = self.net_map.get_or_create_endpoint(dst_ip)
            ep.services.add("http")
            if host_header:
                ep.hostnames.add(host_header)
            if server_header:
                ep.services.add(f"http ({server_header})")
            _update_timestamps(ep, ts)

        if src_ip:
            ep = self.net_map.get_or_create_endpoint(src_ip)
            if user_agent:
                ep.user_agents.add(user_agent)
            _update_timestamps(ep, ts)

        if src_ip and dst_ip and dst_port:
            conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, "tcp")
            conn.service = conn.service or "http"
            if host_header:
                conn.associated_domains.add(host_header)

    def _process_zeek_x509(self, doc: dict):
        ts = _safe(doc, "@timestamp")
        subject = _safe(doc, "x509", "certificate", "subject")
        issuer = _safe(doc, "x509", "certificate", "issuer")
        san = _safe(doc, "x509", "san", "dns")
        not_before = _safe(doc, "x509", "certificate", "not_valid_before")
        not_after = _safe(doc, "x509", "certificate", "not_valid_after")
        # x509 logs don't always have direct IP mapping, but SAN DNS names
        # can be used to enrich endpoints via dns_map
        if san:
            if isinstance(san, str):
                san = [san]
            for name in san:
                for ip_set in [self.net_map.dns_map.get(name, set())]:
                    for ip in ip_set:
                        ep = self.net_map.get_or_create_endpoint(ip)
                        ep.certificates.append({
                            "subject": subject,
                            "issuer": issuer,
                            "san": name,
                            "not_before": not_before,
                            "not_after": not_after,
                        })

    def _process_zeek_software(self, doc: dict):
        ts = _safe(doc, "@timestamp")
        host_ip = _safe(doc, "source", "ip") or _safe(doc, "host", "ip")
        software_type = _safe(doc, "zeek", "software", "software_type")
        name = _safe(doc, "zeek", "software", "name")
        version = _safe(doc, "zeek", "software", "version", "major")

        if host_ip:
            ep = self.net_map.get_or_create_endpoint(host_ip)
            sw_label = f"{name}" if name else software_type
            if sw_label:
                ep.services.add(sw_label)
            if software_type and "os" in software_type.lower():
                ep.os_info.add(name or software_type)
            _update_timestamps(ep, ts)

    def _process_zeek_kerberos(self, doc: dict):
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        client = _safe(doc, "zeek", "kerberos", "client")
        service_name = _safe(doc, "zeek", "kerberos", "service")

        if src_ip:
            ep = self.net_map.get_or_create_endpoint(src_ip)
            ep.protocols.add("kerberos")
            _update_timestamps(ep, ts)
        if dst_ip:
            ep = self.net_map.get_or_create_endpoint(dst_ip)
            ep.services.add("kerberos")
            _update_timestamps(ep, ts)

    # ------------------------------------------------------------------
    # OT/ICS protocol processors
    # ------------------------------------------------------------------

    # Well-known Modbus function codes for device-type inference
    _MODBUS_FUNC_NAMES = {
        1: "read_coils", 2: "read_discrete_inputs", 3: "read_holding_regs",
        4: "read_input_regs", 5: "write_single_coil", 6: "write_single_reg",
        15: "write_multiple_coils", 16: "write_multiple_regs",
        43: "read_device_id",
    }

    def _classify_ot_device(self, ep: Endpoint):
        """Heuristic classification of OT device type based on observed behavior."""
        if ep.device_type:
            return  # Already classified
        protos = ep.ot_protocols
        funcs = ep.ot_functions
        services = ep.services
        ports = set(ep.open_ports.keys())

        # Engineering workstation: initiates ICS connections but also has IT services
        if protos and any(s in services for s in ("http", "ssl/tls", "kerberos", "ssh")):
            ep.device_type = "eng_workstation"
            ep.purdue_level = 3
            return

        # Historian / SCADA server: many connections, runs databases, HTTP
        if protos and ep.connection_count > 50 and any(p in ports for p in (1433, 3306, 5432, 8080)):
            ep.device_type = "historian"
            ep.purdue_level = 3
            return

        # HMI: speaks ICS protocols + has a web UI on common HMI ports
        if protos and any(p in ports for p in (80, 443, 8080, 8443)):
            ep.device_type = "hmi"
            ep.purdue_level = 2
            return

        # RTU: speaks DNP3 (common for remote telemetry)
        if "dnp3" in protos:
            ep.device_type = "rtu"
            ep.purdue_level = 1
            return

        # PLC: speaks modbus/s7comm/enip and has limited other services
        if protos & {"modbus", "s7comm", "enip", "cip"}:
            ep.device_type = "plc"
            ep.purdue_level = 1
            return

        # BACnet device: building automation
        if "bacnet" in protos:
            ep.device_type = "bacnet_device"
            ep.purdue_level = 1
            return

        # Generic OT if has ICS protocols but no clear classification
        if protos:
            ep.device_type = "ot_device"
            ep.purdue_level = 1

    def _process_zeek_modbus(self, doc: dict):
        """Process Zeek modbus.log entries."""
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        dst_port = _safe(doc, "destination", "port", default=502)
        func_code = _safe(doc, "zeek", "modbus", "function")
        exception = _safe(doc, "zeek", "modbus", "exception")
        unit_id = _safe(doc, "zeek", "modbus", "unit_id")

        if not src_ip or not dst_ip:
            return

        # Source is the Modbus master/client (SCADA/HMI)
        src_ep = self.net_map.get_or_create_endpoint(src_ip)
        src_ep.is_internal = _is_internal(src_ip) if src_ep.is_internal is None else src_ep.is_internal
        src_ep.ot_protocols.add("modbus")
        src_ep.protocols.add("modbus")
        _update_timestamps(src_ep, ts)

        # Destination is the Modbus slave/server (PLC/RTU)
        dst_ep = self.net_map.get_or_create_endpoint(dst_ip)
        dst_ep.is_internal = _is_internal(dst_ip) if dst_ep.is_internal is None else dst_ep.is_internal
        dst_ep.ot_protocols.add("modbus")
        dst_ep.protocols.add("modbus")
        dst_ep.services.add("modbus")
        if dst_port:
            if dst_port not in dst_ep.open_ports:
                dst_ep.open_ports[dst_port] = set()
            dst_ep.open_ports[dst_port].add("modbus")
        _update_timestamps(dst_ep, ts)

        # Track function codes
        if func_code is not None:
            func_name = self._MODBUS_FUNC_NAMES.get(func_code, f"fc_{func_code}")
            src_ep.ot_functions.add(f"modbus:{func_name}")
            dst_ep.ot_functions.add(f"modbus:{func_name}")

        # Connection
        conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, "tcp")
        conn.service = "modbus"
        conn.count += 1
        _update_timestamps(conn, ts)

        self._classify_ot_device(src_ep)
        self._classify_ot_device(dst_ep)

    def _process_zeek_dnp3(self, doc: dict):
        """Process Zeek dnp3.log entries."""
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        dst_port = _safe(doc, "destination", "port", default=20000)
        fc_request = _safe(doc, "zeek", "dnp3", "fc_request")
        fc_reply = _safe(doc, "zeek", "dnp3", "fc_reply")
        iin = _safe(doc, "zeek", "dnp3", "iin")

        if not src_ip or not dst_ip:
            return

        src_ep = self.net_map.get_or_create_endpoint(src_ip)
        src_ep.is_internal = _is_internal(src_ip) if src_ep.is_internal is None else src_ep.is_internal
        src_ep.ot_protocols.add("dnp3")
        src_ep.protocols.add("dnp3")
        _update_timestamps(src_ep, ts)

        dst_ep = self.net_map.get_or_create_endpoint(dst_ip)
        dst_ep.is_internal = _is_internal(dst_ip) if dst_ep.is_internal is None else dst_ep.is_internal
        dst_ep.ot_protocols.add("dnp3")
        dst_ep.protocols.add("dnp3")
        dst_ep.services.add("dnp3")
        if dst_port:
            if dst_port not in dst_ep.open_ports:
                dst_ep.open_ports[dst_port] = set()
            dst_ep.open_ports[dst_port].add("dnp3")
        _update_timestamps(dst_ep, ts)

        if fc_request:
            src_ep.ot_functions.add(f"dnp3:req_{fc_request}")
        if fc_reply:
            dst_ep.ot_functions.add(f"dnp3:rsp_{fc_reply}")

        conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, "tcp")
        conn.service = "dnp3"
        conn.count += 1
        _update_timestamps(conn, ts)

        self._classify_ot_device(src_ep)
        self._classify_ot_device(dst_ep)

    def _process_zeek_s7comm(self, doc: dict):
        """Process Zeek s7comm.log entries (Siemens S7 protocol)."""
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        dst_port = _safe(doc, "destination", "port", default=102)
        rosctr = _safe(doc, "zeek", "s7comm", "rosctr")
        func_code = _safe(doc, "zeek", "s7comm", "function_code")
        subfunction = _safe(doc, "zeek", "s7comm", "subfunction")
        error_class = _safe(doc, "zeek", "s7comm", "error_class")

        if not src_ip or not dst_ip:
            return

        src_ep = self.net_map.get_or_create_endpoint(src_ip)
        src_ep.is_internal = _is_internal(src_ip) if src_ep.is_internal is None else src_ep.is_internal
        src_ep.ot_protocols.add("s7comm")
        src_ep.protocols.add("s7comm")
        _update_timestamps(src_ep, ts)

        dst_ep = self.net_map.get_or_create_endpoint(dst_ip)
        dst_ep.is_internal = _is_internal(dst_ip) if dst_ep.is_internal is None else dst_ep.is_internal
        dst_ep.ot_protocols.add("s7comm")
        dst_ep.protocols.add("s7comm")
        dst_ep.services.add("s7comm")
        dst_ep.ot_vendor = dst_ep.ot_vendor or "Siemens"
        if dst_port:
            if dst_port not in dst_ep.open_ports:
                dst_ep.open_ports[dst_port] = set()
            dst_ep.open_ports[dst_port].add("s7comm")
        _update_timestamps(dst_ep, ts)

        if rosctr:
            label = f"s7comm:rosctr_{rosctr}"
            src_ep.ot_functions.add(label)
            dst_ep.ot_functions.add(label)
        if func_code:
            src_ep.ot_functions.add(f"s7comm:func_{func_code}")

        conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, "tcp")
        conn.service = "s7comm"
        conn.count += 1
        _update_timestamps(conn, ts)

        self._classify_ot_device(src_ep)
        self._classify_ot_device(dst_ep)

    def _process_zeek_bacnet(self, doc: dict):
        """Process Zeek bacnet.log entries (Building Automation)."""
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        dst_port = _safe(doc, "destination", "port", default=47808)
        bvlc_function = _safe(doc, "zeek", "bacnet", "bvlc_function")
        service_choice = _safe(doc, "zeek", "bacnet", "service_choice")
        object_type = _safe(doc, "zeek", "bacnet", "object_type")
        vendor = _safe(doc, "zeek", "bacnet", "vendor")

        if not src_ip or not dst_ip:
            return

        src_ep = self.net_map.get_or_create_endpoint(src_ip)
        src_ep.is_internal = _is_internal(src_ip) if src_ep.is_internal is None else src_ep.is_internal
        src_ep.ot_protocols.add("bacnet")
        src_ep.protocols.add("bacnet")
        _update_timestamps(src_ep, ts)

        dst_ep = self.net_map.get_or_create_endpoint(dst_ip)
        dst_ep.is_internal = _is_internal(dst_ip) if dst_ep.is_internal is None else dst_ep.is_internal
        dst_ep.ot_protocols.add("bacnet")
        dst_ep.protocols.add("bacnet")
        dst_ep.services.add("bacnet")
        if vendor:
            dst_ep.ot_vendor = vendor
        if dst_port:
            if dst_port not in dst_ep.open_ports:
                dst_ep.open_ports[dst_port] = set()
            dst_ep.open_ports[dst_port].add("bacnet")
        _update_timestamps(dst_ep, ts)

        if bvlc_function:
            src_ep.ot_functions.add(f"bacnet:bvlc_{bvlc_function}")
        if service_choice:
            src_ep.ot_functions.add(f"bacnet:svc_{service_choice}")

        conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, "udp")
        conn.service = "bacnet"
        conn.count += 1
        _update_timestamps(conn, ts)

        self._classify_ot_device(src_ep)
        self._classify_ot_device(dst_ep)

    def _process_zeek_enip(self, doc: dict):
        """Process Zeek enip.log entries (EtherNet/IP)."""
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        dst_port = _safe(doc, "destination", "port", default=44818)
        command = _safe(doc, "zeek", "enip", "command")
        session_handle = _safe(doc, "zeek", "enip", "session_handle")
        sender_context = _safe(doc, "zeek", "enip", "sender_context")

        if not src_ip or not dst_ip:
            return

        src_ep = self.net_map.get_or_create_endpoint(src_ip)
        src_ep.is_internal = _is_internal(src_ip) if src_ep.is_internal is None else src_ep.is_internal
        src_ep.ot_protocols.add("enip")
        src_ep.protocols.add("enip")
        _update_timestamps(src_ep, ts)

        dst_ep = self.net_map.get_or_create_endpoint(dst_ip)
        dst_ep.is_internal = _is_internal(dst_ip) if dst_ep.is_internal is None else dst_ep.is_internal
        dst_ep.ot_protocols.add("enip")
        dst_ep.protocols.add("enip")
        dst_ep.services.add("enip")
        if dst_port:
            if dst_port not in dst_ep.open_ports:
                dst_ep.open_ports[dst_port] = set()
            dst_ep.open_ports[dst_port].add("enip")
        _update_timestamps(dst_ep, ts)

        if command:
            src_ep.ot_functions.add(f"enip:cmd_{command}")

        conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, "tcp")
        conn.service = "enip"
        conn.count += 1
        _update_timestamps(conn, ts)

        self._classify_ot_device(src_ep)
        self._classify_ot_device(dst_ep)

    def _process_zeek_cip(self, doc: dict):
        """Process Zeek cip.log entries (CIP over EtherNet/IP)."""
        ts = _safe(doc, "@timestamp")
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        dst_port = _safe(doc, "destination", "port", default=44818)
        cip_service = _safe(doc, "zeek", "cip", "service")
        cip_status = _safe(doc, "zeek", "cip", "status")
        class_id = _safe(doc, "zeek", "cip", "class_id")
        instance_id = _safe(doc, "zeek", "cip", "instance_id")
        vendor_id = _safe(doc, "zeek", "cip", "vendor_id")
        device_type = _safe(doc, "zeek", "cip", "device_type")
        product_name = _safe(doc, "zeek", "cip", "product_name")

        if not src_ip or not dst_ip:
            return

        src_ep = self.net_map.get_or_create_endpoint(src_ip)
        src_ep.is_internal = _is_internal(src_ip) if src_ep.is_internal is None else src_ep.is_internal
        src_ep.ot_protocols.add("cip")
        src_ep.protocols.add("cip")
        _update_timestamps(src_ep, ts)

        dst_ep = self.net_map.get_or_create_endpoint(dst_ip)
        dst_ep.is_internal = _is_internal(dst_ip) if dst_ep.is_internal is None else dst_ep.is_internal
        dst_ep.ot_protocols.add("cip")
        dst_ep.protocols.add("cip")
        dst_ep.services.add("cip")
        if product_name:
            dst_ep.ot_vendor = product_name
        if dst_port:
            if dst_port not in dst_ep.open_ports:
                dst_ep.open_ports[dst_port] = set()
            dst_ep.open_ports[dst_port].add("cip")
        _update_timestamps(dst_ep, ts)

        if cip_service:
            src_ep.ot_functions.add(f"cip:svc_{cip_service}")

        conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, "tcp")
        conn.service = "cip"
        conn.count += 1
        _update_timestamps(conn, ts)

        self._classify_ot_device(src_ep)
        self._classify_ot_device(dst_ep)

    # ------------------------------------------------------------------
    # Sysmon processors
    # ------------------------------------------------------------------

    def _process_sysmon_network(self, doc: dict):
        """Sysmon Event ID 3 - Network Connection Detected."""
        ts = _safe(doc, "@timestamp")
        # Sysmon network events in Security Onion/ECS
        src_ip = _safe(doc, "source", "ip")
        dst_ip = _safe(doc, "destination", "ip")
        src_port = _safe(doc, "source", "port")
        dst_port = _safe(doc, "destination", "port", default=0)
        proto = _safe(doc, "network", "transport", default="unknown")
        process_name = _safe(doc, "process", "name")
        process_exe = _safe(doc, "process", "executable")
        process_pid = _safe(doc, "process", "pid")
        user = _safe(doc, "user", "name")
        computer = _safe(doc, "host", "name") or _safe(doc, "winlog", "computer_name")

        if src_ip:
            ep = self.net_map.get_or_create_endpoint(src_ip)
            ep.is_internal = _is_internal(src_ip) if ep.is_internal is None else ep.is_internal
            if computer:
                ep.sysmon_computer_name = computer
                ep.hostnames.add(computer)
            if process_name:
                proc_entry = {
                    "name": process_name,
                    "exe": process_exe,
                    "pid": process_pid,
                    "user": user,
                    "dst": f"{dst_ip}:{dst_port}" if dst_ip else None,
                    "timestamp": ts,
                }
                # Avoid duplicating identical process entries
                if not any(
                    p.get("name") == process_name and p.get("dst") == proc_entry["dst"]
                    for p in ep.processes
                ):
                    ep.processes.append(proc_entry)
            _update_timestamps(ep, ts)

        if dst_ip:
            ep = self.net_map.get_or_create_endpoint(dst_ip)
            ep.is_internal = _is_internal(dst_ip) if ep.is_internal is None else ep.is_internal
            if dst_port:
                if dst_port not in ep.open_ports:
                    ep.open_ports[dst_port] = set()
                ep.open_ports[dst_port].add(process_name or proto)
            _update_timestamps(ep, ts)

        if src_ip and dst_ip and dst_port:
            conn = self.net_map.get_or_create_connection(src_ip, dst_ip, dst_port, proto)
            conn.count += 1
            _update_timestamps(conn, ts)

    def _process_sysmon_process(self, doc: dict):
        """Sysmon Event ID 1 - Process Create."""
        ts = _safe(doc, "@timestamp")
        computer = _safe(doc, "host", "name") or _safe(doc, "winlog", "computer_name")
        host_ip = _safe(doc, "host", "ip")
        process_name = _safe(doc, "process", "name")
        process_exe = _safe(doc, "process", "executable")
        process_pid = _safe(doc, "process", "pid")
        process_cmd = _safe(doc, "process", "command_line")
        parent_name = _safe(doc, "process", "parent", "name")
        parent_exe = _safe(doc, "process", "parent", "executable")
        user = _safe(doc, "user", "name")
        hashes = _safe(doc, "zeek") or _safe(doc, "winlog", "event_data", "Hashes")

        # host.ip can be a list in Security Onion
        if isinstance(host_ip, list):
            ips = host_ip
        elif host_ip:
            ips = [host_ip]
        else:
            ips = []

        for ip in ips:
            if ip.startswith("fe80:") or ip == "::1" or ip == "127.0.0.1":
                continue
            ep = self.net_map.get_or_create_endpoint(ip)
            ep.is_internal = _is_internal(ip) if ep.is_internal is None else ep.is_internal
            if computer:
                ep.sysmon_computer_name = computer
                ep.hostnames.add(computer)
            proc_entry = {
                "name": process_name,
                "exe": process_exe,
                "pid": process_pid,
                "command_line": process_cmd,
                "parent": parent_name or parent_exe,
                "user": user,
                "timestamp": ts,
            }
            # Keep unique by name+exe combo to avoid explosion
            if not any(
                p.get("name") == process_name and p.get("exe") == process_exe
                for p in ep.processes
            ):
                ep.processes.append(proc_entry)
            _update_timestamps(ep, ts)

    def _process_sysmon_dns(self, doc: dict):
        """Sysmon Event ID 22 - DNS Query."""
        ts = _safe(doc, "@timestamp")
        host_ip = _safe(doc, "host", "ip")
        query_name = _safe(doc, "dns", "question", "name")
        query_result = _safe(doc, "dns", "answers")
        computer = _safe(doc, "host", "name") or _safe(doc, "winlog", "computer_name")
        process_name = _safe(doc, "process", "name")

        if isinstance(host_ip, list):
            ips = host_ip
        elif host_ip:
            ips = [host_ip]
        else:
            ips = []

        for ip in ips:
            if ip.startswith("fe80:") or ip == "::1" or ip == "127.0.0.1":
                continue
            ep = self.net_map.get_or_create_endpoint(ip)
            ep.is_internal = _is_internal(ip) if ep.is_internal is None else ep.is_internal
            if computer:
                ep.sysmon_computer_name = computer
                ep.hostnames.add(computer)
            if query_name:
                ep.dns_queries.add(query_name)
            _update_timestamps(ep, ts)
