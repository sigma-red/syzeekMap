"""Data models for network map entities."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Endpoint:
    """Represents a host/IP on the network."""

    ip: str
    hostnames: set[str] = field(default_factory=set)
    mac_addresses: set[str] = field(default_factory=set)
    os_info: set[str] = field(default_factory=set)
    open_ports: dict[int, set[str]] = field(default_factory=dict)  # port -> protocols/services
    services: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    dns_queries: set[str] = field(default_factory=set)
    processes: list[dict] = field(default_factory=list)
    certificates: list[dict] = field(default_factory=list)
    user_agents: set[str] = field(default_factory=set)
    is_internal: Optional[bool] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    connection_count: int = 0
    sysmon_computer_name: Optional[str] = None
    # OT/ICS fields
    device_type: Optional[str] = None  # plc, hmi, rtu, historian, eng_workstation, scada_server
    ot_protocols: set[str] = field(default_factory=set)  # modbus, dnp3, s7comm, bacnet, enip
    ot_vendor: Optional[str] = None
    ot_functions: set[str] = field(default_factory=set)  # Modbus func codes, DNP3 obj groups, etc.
    purdue_level: Optional[int] = None  # Estimated Purdue model level (0-5)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostnames": sorted(self.hostnames),
            "mac_addresses": sorted(self.mac_addresses),
            "os_info": sorted(self.os_info),
            "open_ports": {
                str(p): sorted(s) for p, s in sorted(self.open_ports.items())
            },
            "services": sorted(self.services),
            "protocols": sorted(self.protocols),
            "dns_queries": sorted(list(self.dns_queries)[:100]),
            "processes": self.processes[:100],
            "certificates": self.certificates[:50],
            "user_agents": sorted(list(self.user_agents)[:20]),
            "is_internal": self.is_internal,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "total_bytes_sent": self.total_bytes_sent,
            "total_bytes_received": self.total_bytes_received,
            "connection_count": self.connection_count,
            "sysmon_computer_name": self.sysmon_computer_name,
            "device_type": self.device_type,
            "ot_protocols": sorted(self.ot_protocols),
            "ot_vendor": self.ot_vendor,
            "ot_functions": sorted(list(self.ot_functions)[:50]),
            "purdue_level": self.purdue_level,
        }

    @property
    def subnet(self) -> str:
        """Return the /24 subnet for this IP (used for visual grouping)."""
        try:
            addr = ipaddress.ip_address(self.ip)
            if isinstance(addr, ipaddress.IPv4Address):
                net = ipaddress.IPv4Network(f"{self.ip}/24", strict=False)
                return str(net)
            return str(ipaddress.IPv6Network(f"{self.ip}/64", strict=False))
        except ValueError:
            return "unknown"

    def to_node(self) -> dict:
        """Compact representation for graph visualization."""
        label = self.ip
        if self.hostnames:
            label = sorted(self.hostnames)[0]
        elif self.sysmon_computer_name:
            label = self.sysmon_computer_name
        return {
            "id": self.ip,
            "label": label,
            "ip": self.ip,
            "is_internal": self.is_internal,
            "subnet": self.subnet,
            "services": sorted(self.services),
            "open_port_count": len(self.open_ports),
            "connection_count": self.connection_count,
            "os_info": sorted(self.os_info),
            "device_type": self.device_type,
            "ot_protocols": sorted(self.ot_protocols),
            "purdue_level": self.purdue_level,
        }


@dataclass
class Connection:
    """Represents an aggregated connection between two endpoints."""

    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    service: str = ""
    total_bytes: int = 0
    total_packets: int = 0
    count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    conn_states: set[str] = field(default_factory=set)
    history: set[str] = field(default_factory=set)
    associated_domains: set[str] = field(default_factory=set)
    ja3_hashes: set[str] = field(default_factory=set)

    @property
    def edge_id(self) -> str:
        return f"{self.src_ip}->{self.dst_ip}:{self.dst_port}/{self.proto}"

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "service": self.service,
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "conn_states": sorted(self.conn_states),
            "history": sorted(self.history),
            "associated_domains": sorted(self.associated_domains),
            "ja3_hashes": sorted(self.ja3_hashes),
        }

    def to_edge(self) -> dict:
        """Compact representation for graph visualization."""
        label = self.service or self.proto
        if self.dst_port:
            label = f"{label}:{self.dst_port}"
        return {
            "id": self.edge_id,
            "source": self.src_ip,
            "target": self.dst_ip,
            "label": label,
            "port": self.dst_port,
            "proto": self.proto,
            "service": self.service,
            "count": self.count,
            "total_bytes": self.total_bytes,
        }


@dataclass
class NetworkMap:
    """Central state holding the full network map."""

    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    connections: dict[str, Connection] = field(default_factory=dict)
    dns_map: dict[str, set[str]] = field(default_factory=dict)  # domain -> IPs
    last_poll_time: Optional[str] = None
    version: int = 0  # Incremented on each update for change detection

    def get_or_create_endpoint(self, ip: str) -> Endpoint:
        if ip not in self.endpoints:
            self.endpoints[ip] = Endpoint(ip=ip)
        return self.endpoints[ip]

    def get_or_create_connection(
        self, src_ip: str, dst_ip: str, dst_port: int, proto: str
    ) -> Connection:
        key = f"{src_ip}->{dst_ip}:{dst_port}/{proto}"
        if key not in self.connections:
            self.connections[key] = Connection(
                src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port, proto=proto
            )
        return self.connections[key]

    def to_graph(self) -> dict:
        """Return full graph data for visualization."""
        nodes = [ep.to_node() for ep in self.endpoints.values()]
        edges_by_pair: dict[str, dict] = {}
        for conn in self.connections.values():
            pair_key = f"{conn.src_ip}->{conn.dst_ip}"
            if pair_key not in edges_by_pair:
                edges_by_pair[pair_key] = {
                    "id": pair_key,
                    "source": conn.src_ip,
                    "target": conn.dst_ip,
                    "services": set(),
                    "ports": set(),
                    "total_bytes": 0,
                    "count": 0,
                }
            e = edges_by_pair[pair_key]
            if conn.service:
                e["services"].add(conn.service)
            e["ports"].add(conn.dst_port)
            e["total_bytes"] += conn.total_bytes
            e["count"] += conn.count

        edges = []
        for e in edges_by_pair.values():
            e["services"] = sorted(e["services"])
            e["ports"] = sorted(e["ports"])
            label_parts = e["services"][:3] if e["services"] else [str(p) for p in e["ports"][:3]]
            e["label"] = ", ".join(label_parts)
            edges.append(e)

        return {
            "nodes": nodes,
            "edges": edges,
            "version": self.version,
            "last_updated": self.last_poll_time,
            "endpoint_count": len(self.endpoints),
            "connection_count": len(self.connections),
        }

    def get_stats(self) -> dict:
        internal = sum(1 for e in self.endpoints.values() if e.is_internal)
        external = sum(1 for e in self.endpoints.values() if e.is_internal is False)
        unknown = sum(1 for e in self.endpoints.values() if e.is_internal is None)
        ot_devices = sum(1 for e in self.endpoints.values() if e.ot_protocols)
        return {
            "total_endpoints": len(self.endpoints),
            "internal_endpoints": internal,
            "external_endpoints": external,
            "unknown_endpoints": unknown,
            "ot_devices": ot_devices,
            "total_connections": len(self.connections),
            "total_dns_domains": len(self.dns_map),
            "version": self.version,
            "last_updated": self.last_poll_time,
        }
