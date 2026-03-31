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

## Deployment

### Option A: Run Directly on Security Onion Manager

#### 1. Install dependencies

```bash
pip install -r requirements.txt
```

#### 2. Configure

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
HOST=0.0.0.0
PORT=8080
```

#### 3. Run

```bash
python app.py
```

Open `http://<manager-ip>:8080` in your browser.

### Option B: Docker (Recommended for Air-Gapped Environments)

A `Dockerfile` and helper script are included for building a self-contained image on an internet-connected machine and transferring it to an air-gapped Security Onion manager.

#### On the internet-connected build machine

```bash
# Build the image and export it to a portable .tar.gz
./deploy-airgap.sh build
```

This produces `syzeekmap-image.tar.gz` (~80-100 MB) containing all Python dependencies and a vendored copy of D3.js.

#### Transfer to the air-gapped SO manager

Copy the following files via USB or other sneakernet method:
- `syzeekmap-image.tar.gz`
- `deploy-airgap.sh`
- `.env.example`

#### On the air-gapped SO manager

```bash
# Load the image
./deploy-airgap.sh load

# Create and edit your config
cp .env.example .env
# Edit .env with your SO Elasticsearch credentials

# Start the container
./deploy-airgap.sh run

# Stop when needed
./deploy-airgap.sh stop
```

The container runs with `--network host` so it can reach Elasticsearch on `localhost:9200` without Docker bridge networking.

If you have `docker compose` available you can also use:
```bash
docker compose up -d
```

### Security Onion Firewall Configuration

Security Onion manages its firewall with Salt. To access syzeekMap from an analyst workstation you need to open the port through SO's firewall — adding it to the **nginx** portgroup will **not** work since syzeekMap runs as a standalone service, not behind nginx.

1. **Create a portgroup** in `SOC UI → Administration → Configuration → Firewall → portgroups`:
   - Name: `syzeekmap`
   - Value: `tcp/8080` (or whatever port you configured)

2. **Add your analyst workstation IP** to a hostgroup (e.g., `analyst`) under `Firewall → hostgroups`, if not already present.

3. **Map the hostgroup to the portgroup** under the role's firewall settings so the analyst hostgroup is allowed to reach the `syzeekmap` portgroup.

4. **Apply the firewall changes**:
   ```bash
   sudo salt-call state.apply firewall
   ```

5. **Verify**:
   ```bash
   sudo iptables -L INPUT -n | grep 8080
   ```

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
