"""syzeekMap - Passive Network Mapping Tool

FastAPI application that serves the API and web frontend.
Runs a background polling loop to continuously ingest Zeek/Sysmon data.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from config import Config
from elastic_client import ElasticClient
from ingest import IngestEngine
from models import NetworkMap

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("syzeekmap")

# Global state
network_map = NetworkMap()
es_client = ElasticClient()
ingest_engine = IngestEngine(es_client, network_map)
connected_websockets: set[WebSocket] = set()


async def poll_loop():
    """Background task that continuously polls Elasticsearch."""
    logger.info("Starting poll loop (interval=%ds)", Config.POLL_INTERVAL)
    while True:
        try:
            await asyncio.to_thread(ingest_engine.run_poll_cycle)
            # Notify all connected WebSocket clients
            await broadcast_update()
        except Exception as e:
            logger.error("Poll cycle error: %s", e, exc_info=True)
        await asyncio.sleep(Config.POLL_INTERVAL)


async def broadcast_update():
    """Send a lightweight update notification to all WebSocket clients."""
    if not connected_websockets:
        return
    msg = json.dumps({
        "type": "update",
        "version": network_map.version,
        "stats": network_map.get_stats(),
    })
    stale = set()
    for ws in connected_websockets:
        try:
            await ws.send_text(msg)
        except Exception:
            stale.add(ws)
    connected_websockets.difference_update(stale)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the background polling task on startup."""
    logger.info("syzeekMap starting up...")
    if es_client.test_connection():
        logger.info("Elasticsearch connection successful")
    else:
        logger.warning("Elasticsearch connection failed - will retry on poll")
    task = asyncio.create_task(poll_loop())
    yield
    task.cancel()
    logger.info("syzeekMap shutting down")


app = FastAPI(title="syzeekMap", lifespan=lifespan)

# Serve static files
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# ------------------------------------------------------------------
# API Routes
# ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main web UI."""
    index_file = static_dir / "index.html"
    if index_file.exists():
        return HTMLResponse(index_file.read_text())
    return HTMLResponse("<h1>syzeekMap</h1><p>Static files not found.</p>")


@app.get("/api/graph")
async def get_graph():
    """Return full graph data for visualization."""
    return JSONResponse(network_map.to_graph())


@app.get("/api/stats")
async def get_stats():
    """Return summary statistics."""
    return JSONResponse(network_map.get_stats())


@app.get("/api/endpoints")
async def list_endpoints(
    internal_only: bool = Query(False),
    external_only: bool = Query(False),
    search: str = Query(""),
):
    """List all endpoints with optional filters."""
    results = []
    for ep in network_map.endpoints.values():
        if internal_only and not ep.is_internal:
            continue
        if external_only and ep.is_internal:
            continue
        if search:
            q = search.lower()
            match = (
                q in ep.ip.lower()
                or any(q in h.lower() for h in ep.hostnames)
                or (ep.sysmon_computer_name and q in ep.sysmon_computer_name.lower())
                or any(q in s.lower() for s in ep.services)
            )
            if not match:
                continue
        results.append(ep.to_node())
    results.sort(key=lambda x: x["connection_count"], reverse=True)
    return JSONResponse(results)


@app.get("/api/endpoints/{ip}")
async def get_endpoint(ip: str):
    """Return full details for a specific endpoint."""
    ep = network_map.endpoints.get(ip)
    if not ep:
        return JSONResponse({"error": "Endpoint not found"}, status_code=404)
    # Also include connections involving this endpoint
    related_connections = [
        c.to_dict()
        for c in network_map.connections.values()
        if c.src_ip == ip or c.dst_ip == ip
    ]
    data = ep.to_dict()
    data["connections"] = sorted(related_connections, key=lambda c: c["count"], reverse=True)
    return JSONResponse(data)


@app.get("/api/connections")
async def list_connections(
    src: str = Query(""),
    dst: str = Query(""),
    port: int = Query(0),
    service: str = Query(""),
):
    """List connections with optional filters."""
    results = []
    for conn in network_map.connections.values():
        if src and conn.src_ip != src:
            continue
        if dst and conn.dst_ip != dst:
            continue
        if port and conn.dst_port != port:
            continue
        if service and service.lower() not in conn.service.lower():
            continue
        results.append(conn.to_dict())
    results.sort(key=lambda c: c["count"], reverse=True)
    return JSONResponse(results[:500])


@app.get("/api/dns")
async def get_dns_map(search: str = Query("")):
    """Return the DNS domain-to-IP mapping."""
    result = {}
    for domain, ips in network_map.dns_map.items():
        if search and search.lower() not in domain.lower():
            continue
        result[domain] = sorted(ips)
    return JSONResponse(result)


# ------------------------------------------------------------------
# WebSocket for live updates
# ------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_websockets.add(ws)
    logger.info("WebSocket client connected (%d total)", len(connected_websockets))
    try:
        # Send initial state
        await ws.send_text(json.dumps({
            "type": "init",
            "version": network_map.version,
            "stats": network_map.get_stats(),
        }))
        # Keep alive - listen for client messages
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
            elif data == "graph":
                await ws.send_text(json.dumps({
                    "type": "graph",
                    "data": network_map.to_graph(),
                }))
    except WebSocketDisconnect:
        pass
    finally:
        connected_websockets.discard(ws)
        logger.info("WebSocket client disconnected (%d remaining)", len(connected_websockets))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host=Config.HOST, port=Config.PORT, reload=False)
