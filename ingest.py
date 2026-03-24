"""Ingestion and correlation engine.

Processes raw Zeek and Sysmon log data from Elasticsearch and builds/updates
the central NetworkMap model.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone

from elastic_client import ElasticClient
from models import NetworkMap

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


class IngestEngine:
    """Pulls data from Elasticsearch and updates the NetworkMap."""

    def __init__(self, es_client: ElasticClient, network_map: NetworkMap):
        self.es = es_client
        self.net_map = network_map
        self._last_timestamp: str | None = None

    def run_poll_cycle(self):
        """Execute a full poll cycle, fetching new data since last poll."""
        since = self._last_timestamp
        now = datetime.now(timezone.utc).isoformat()
        logger.info("Poll cycle started (since=%s)", since or "beginning")

        counts = {
            "zeek_conn": 0,
            "zeek_dns": 0,
            "zeek_ssl": 0,
            "zeek_http": 0,
            "zeek_x509": 0,
            "zeek_software": 0,
            "zeek_kerberos": 0,
            "sysmon_net": 0,
            "sysmon_proc": 0,
            "sysmon_dns": 0,
        }

        # --- Zeek conn.log ---
        for doc in self.es.fetch_zeek_conn(since):
            self._process_zeek_conn(doc)
            counts["zeek_conn"] += 1

        # --- Zeek dns.log ---
        for doc in self.es.fetch_zeek_dns(since):
            self._process_zeek_dns(doc)
            counts["zeek_dns"] += 1

        # --- Zeek ssl.log ---
        for doc in self.es.fetch_zeek_ssl(since):
            self._process_zeek_ssl(doc)
            counts["zeek_ssl"] += 1

        # --- Zeek http.log ---
        for doc in self.es.fetch_zeek_http(since):
            self._process_zeek_http(doc)
            counts["zeek_http"] += 1

        # --- Zeek x509 ---
        for doc in self.es.fetch_zeek_x509(since):
            self._process_zeek_x509(doc)
            counts["zeek_x509"] += 1

        # --- Zeek software ---
        for doc in self.es.fetch_zeek_software(since):
            self._process_zeek_software(doc)
            counts["zeek_software"] += 1

        # --- Zeek kerberos ---
        for doc in self.es.fetch_zeek_kerberos(since):
            self._process_zeek_kerberos(doc)
            counts["zeek_kerberos"] += 1

        # --- Sysmon network connections (Event ID 3) ---
        for doc in self.es.fetch_sysmon_network(since):
            self._process_sysmon_network(doc)
            counts["sysmon_net"] += 1

        # --- Sysmon process creation (Event ID 1) ---
        for doc in self.es.fetch_sysmon_process_create(since):
            self._process_sysmon_process(doc)
            counts["sysmon_proc"] += 1

        # --- Sysmon DNS (Event ID 22) ---
        for doc in self.es.fetch_sysmon_dns(since):
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
