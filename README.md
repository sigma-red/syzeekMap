# syzeekMap

Passive network mapping tool that correlates Zeek and Sysmon data from Security Onion / Elastic Stack to build a live, interactive network map.

## What It Does

- **Ingests** Zeek logs (conn, dns, ssl, http, x509, software, kerberos) and Sysmon events (process creation, network connections, DNS queries) from Elasticsearch
- **Correlates** network-level data (Zeek) with host-level data (Sysmon) to build endpoint profiles
- **Maps** all observed endpoints, connections, services, and protocols into an interactive force-directed graph
- **Profiles** each endpoint with: IPs, hostnames, MAC addresses, OS info, open ports, services, protocols, DNS queries, processes, certificates, user agents, and traffic volumes
- **Updates continuously** by polling Elasticsearch on a configurable interval with WebSocket push to the browser

## Architecture

```
Elasticsearch (Security Onion)
        │
        ▼
  ┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
  │ ElasticClient│────▶│ IngestEngine │────▶│   NetworkMap     │
  │ (queries)    │     │ (correlates) │     │ (state model)   │
  └─────────────┘     └──────────────┘     └────────┬────────┘
                                                     │
                                              FastAPI + WebSocket
                                                     │
                                              ┌──────▼──────┐
                                              │  Web UI      │
                                              │  (D3.js)     │
                                              └─────────────┘
```

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

Copy the example environment file and fill in your Security Onion Elasticsearch details:

```bash
cp .env.example .env
```

Edit `.env`:
```
ES_HOST=https://<security-onion-manager>:9200
ES_USERNAME=elastic
ES_PASSWORD=<your-password>
ES_VERIFY_CERTS=false
POLL_INTERVAL=30
```

### 3. Run

```bash
python app.py
```

Open `http://localhost:8080` in your browser.

## Data Sources

### Zeek Indices (`*:so-zeek-*`)

| Log | Data Extracted |
|-----|----------------|
| conn.log | IPs, ports, protocols, services, bytes, packets, MAC addresses, connection state |
| dns.log | DNS queries, resolved IPs, domain-to-IP mapping |
| ssl.log | TLS certificates, JA3 hashes, server names, issuers |
| http.log | HTTP hosts, URIs, user agents, server headers |
| x509.log | Certificate subjects, issuers, SANs, validity periods |
| software.log | Software types, versions, OS detection |
| kerberos.log | Kerberos clients and services |

### Sysmon Indices (`*:so-sysmon-*`)

| Event ID | Data Extracted |
|----------|----------------|
| 1 - Process Create | Process name, executable, command line, parent process, user, host IP mapping |
| 3 - Network Connection | Source/dest IPs and ports, initiating process, protocol, computer name |
| 22 - DNS Query | Queried domain, associated process, host IP mapping |

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/graph` | Full graph data (nodes + edges) for visualization |
| `GET /api/stats` | Summary statistics |
| `GET /api/endpoints` | List endpoints (supports `?search=`, `?internal_only=true`, `?external_only=true`) |
| `GET /api/endpoints/{ip}` | Full endpoint profile with all related connections |
| `GET /api/connections` | List connections (supports `?src=`, `?dst=`, `?port=`, `?service=`) |
| `GET /api/dns` | DNS domain-to-IP mapping (supports `?search=`) |
| `WS /ws` | WebSocket for live update notifications |

## Web UI Features

- **Force-directed network graph** with zoom, pan, drag
- **Color-coded nodes**: blue = internal, red = external, gray = unknown
- **Node size** scales with connection count
- **Edge thickness** scales with flow count
- **Search and filter** by IP, hostname, or service
- **Click any node** to drill into full endpoint details
- **Live updates** via WebSocket — graph refreshes automatically as new data is ingested
- **Connection drill-down** from endpoint details — click any remote IP to navigate
