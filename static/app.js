/**
 * syzeekMap - Frontend Application
 *
 * D3.js force-directed graph visualization with live WebSocket updates,
 * endpoint search/filter, and detailed drill-down panels.
 */

(function () {
    "use strict";

    // ── State ──────────────────────────────────────────────────────
    let graphData = { nodes: [], edges: [] };
    let currentVersion = 0;
    let ws = null;
    let simulation = null;
    let selectedNodeId = null;

    // D3 selections (initialized in initGraph)
    let svg, container, linkGroup, nodeGroup, labelGroup, linkLabelGroup;
    let zoom;

    // ── Initialization ─────────────────────────────────────────────
    document.addEventListener("DOMContentLoaded", () => {
        initGraph();
        initControls();
        connectWebSocket();
        fetchGraph();
    });

    // ── Graph Setup ────────────────────────────────────────────────
    function initGraph() {
        svg = d3.select("#graph-svg");
        const width = svg.node().parentElement.clientWidth;
        const height = svg.node().parentElement.clientHeight;

        // Zoom behavior
        zoom = d3.zoom()
            .scaleExtent([0.1, 8])
            .on("zoom", (event) => {
                container.attr("transform", event.transform);
            });
        svg.call(zoom);

        container = svg.append("g");

        // Arrow marker for directed edges
        svg.append("defs").append("marker")
            .attr("id", "arrowhead")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 20)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-4L10,0L0,4")
            .attr("fill", "#334155");

        linkGroup = container.append("g").attr("class", "links");
        linkLabelGroup = container.append("g").attr("class", "link-labels");
        nodeGroup = container.append("g").attr("class", "nodes");
        labelGroup = container.append("g").attr("class", "labels");

        simulation = d3.forceSimulation()
            .force("link", d3.forceLink().id(d => d.id).distance(120))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(30))
            .on("tick", ticked);

        // Handle window resize
        window.addEventListener("resize", () => {
            const w = svg.node().parentElement.clientWidth;
            const h = svg.node().parentElement.clientHeight;
            simulation.force("center", d3.forceCenter(w / 2, h / 2));
        });
    }

    function updateGraph(data) {
        graphData = data;
        const nodes = data.nodes || [];
        const edges = data.edges || [];

        // ── Links ──
        const link = linkGroup.selectAll("line")
            .data(edges, d => d.id);

        link.exit().remove();

        const linkEnter = link.enter().append("line")
            .attr("class", "link")
            .attr("marker-end", "url(#arrowhead)")
            .on("mouseover", (event, d) => showEdgeTooltip(event, d))
            .on("mouseout", hideTooltip);

        linkEnter.merge(link)
            .attr("stroke-width", d => Math.max(1, Math.min(4, Math.log2(d.count + 1))));

        // ── Link labels ──
        const linkLabel = linkLabelGroup.selectAll("text")
            .data(edges, d => d.id);

        linkLabel.exit().remove();

        linkLabel.enter().append("text")
            .attr("class", "link-label")
            .merge(linkLabel)
            .text(d => d.label);

        // ── Nodes ──
        const node = nodeGroup.selectAll("g.node")
            .data(nodes, d => d.id);

        node.exit().remove();

        const nodeEnter = node.enter().append("g")
            .attr("class", "node")
            .call(d3.drag()
                .on("start", dragStarted)
                .on("drag", dragged)
                .on("end", dragEnded))
            .on("click", (event, d) => selectNode(d.id))
            .on("mouseover", (event, d) => showNodeTooltip(event, d))
            .on("mouseout", hideTooltip);

        nodeEnter.append("circle")
            .attr("r", d => nodeRadius(d))
            .attr("fill", d => nodeColor(d))
            .attr("stroke", d => d3.color(nodeColor(d)).brighter(0.5));

        nodeEnter.append("text")
            .attr("dy", d => nodeRadius(d) + 12)
            .attr("text-anchor", "middle")
            .text(d => truncate(d.label, 20));

        // Update existing
        nodeGroup.selectAll("g.node").select("circle")
            .attr("r", d => nodeRadius(d))
            .attr("fill", d => nodeColor(d))
            .attr("stroke", d => selectedNodeId === d.id ? "#fff" : d3.color(nodeColor(d)).brighter(0.5))
            .attr("stroke-width", d => selectedNodeId === d.id ? 3 : 2);

        // ── Simulation ──
        simulation.nodes(nodes);
        simulation.force("link").links(edges);
        simulation.alpha(0.3).restart();

        updateEndpointList(nodes);
    }

    function ticked() {
        linkGroup.selectAll("line")
            .attr("x1", d => d.source.x)
            .attr("y1", d => d.source.y)
            .attr("x2", d => d.target.x)
            .attr("y2", d => d.target.y);

        linkLabelGroup.selectAll("text")
            .attr("x", d => (d.source.x + d.target.x) / 2)
            .attr("y", d => (d.source.y + d.target.y) / 2);

        nodeGroup.selectAll("g.node")
            .attr("transform", d => `translate(${d.x},${d.y})`);
    }

    // ── Node helpers ───────────────────────────────────────────────
    function nodeColor(d) {
        if (d.is_internal === true) return "#3b82f6";
        if (d.is_internal === false) return "#ef4444";
        return "#64748b";
    }

    function nodeRadius(d) {
        return Math.max(6, Math.min(20, 4 + Math.log2(d.connection_count + 1) * 3));
    }

    // ── Drag handlers ──────────────────────────────────────────────
    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.1).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }
    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }

    // ── Tooltips ───────────────────────────────────────────────────
    const tooltip = document.getElementById("graph-tooltip");

    function showNodeTooltip(event, d) {
        let html = `<div class="tt-ip">${d.ip}</div>`;
        if (d.label !== d.ip) html += `<div class="tt-label">${d.label}</div>`;
        html += `<div class="tt-line">Connections: ${d.connection_count}</div>`;
        html += `<div class="tt-line">Ports: ${d.open_port_count}</div>`;
        if (d.services.length) html += `<div class="tt-line">Services: ${d.services.join(", ")}</div>`;
        if (d.os_info.length) html += `<div class="tt-line">OS: ${d.os_info.join(", ")}</div>`;
        tooltip.innerHTML = html;
        tooltip.style.left = event.pageX + 12 + "px";
        tooltip.style.top = event.pageY - 20 + "px";
        tooltip.classList.remove("hidden");
    }

    function showEdgeTooltip(event, d) {
        let html = `<div class="tt-ip">${d.source.id || d.source} &rarr; ${d.target.id || d.target}</div>`;
        html += `<div class="tt-line">${d.label}</div>`;
        html += `<div class="tt-line">Flows: ${d.count} | ${formatBytes(d.total_bytes)}</div>`;
        tooltip.innerHTML = html;
        tooltip.style.left = event.pageX + 12 + "px";
        tooltip.style.top = event.pageY - 20 + "px";
        tooltip.classList.remove("hidden");
    }

    function hideTooltip() {
        tooltip.classList.add("hidden");
    }

    // ── Sidebar endpoint list ──────────────────────────────────────
    function updateEndpointList(nodes) {
        const list = document.getElementById("endpoint-list");
        const sorted = [...nodes].sort((a, b) => b.connection_count - a.connection_count);

        document.getElementById("endpoint-count").textContent = sorted.length;

        list.innerHTML = sorted.map(n => {
            const tag = n.is_internal === true ? '<span class="ep-tag internal">INT</span>'
                : n.is_internal === false ? '<span class="ep-tag external">EXT</span>' : '';
            const label = n.label !== n.ip ? `<div class="ep-label">${escapeHtml(n.label)}</div>` : '';
            const services = n.services.length ? n.services.slice(0, 3).join(", ") : "";
            const meta = services ? `<div class="ep-meta">${escapeHtml(services)}</div>` : "";
            const active = selectedNodeId === n.id ? " active" : "";
            return `<div class="endpoint-item${active}" data-ip="${n.id}">
                <div class="ep-ip">${tag} ${escapeHtml(n.ip)}</div>
                ${label}${meta}
            </div>`;
        }).join("");

        // Click handlers
        list.querySelectorAll(".endpoint-item").forEach(el => {
            el.addEventListener("click", () => selectNode(el.dataset.ip));
        });
    }

    // ── Node selection & detail panel ──────────────────────────────
    async function selectNode(ip) {
        selectedNodeId = ip;

        // Highlight in graph
        nodeGroup.selectAll("g.node").select("circle")
            .attr("stroke", d => d.id === ip ? "#fff" : d3.color(nodeColor(d)).brighter(0.5))
            .attr("stroke-width", d => d.id === ip ? 3 : 2);

        // Highlight in list
        document.querySelectorAll(".endpoint-item").forEach(el => {
            el.classList.toggle("active", el.dataset.ip === ip);
        });

        // Fetch full details
        const panel = document.getElementById("detail-panel");
        const content = document.getElementById("detail-content");
        const title = document.getElementById("detail-title");

        panel.classList.remove("hidden");
        title.textContent = ip;
        content.innerHTML = '<div style="color:var(--text-muted);padding:20px;">Loading...</div>';

        try {
            const resp = await fetch(`/api/endpoints/${encodeURIComponent(ip)}`);
            const data = await resp.json();
            if (data.error) {
                content.innerHTML = `<p style="color:var(--accent-red)">${data.error}</p>`;
                return;
            }
            renderEndpointDetail(data, content);
        } catch (e) {
            content.innerHTML = `<p style="color:var(--accent-red)">Failed to load details</p>`;
        }
    }

    function renderEndpointDetail(ep, container) {
        let html = "";

        // ── Overview ──
        html += `<div class="detail-section"><h4>Overview</h4><div class="detail-grid">`;
        html += gridRow("IP Address", ep.ip);
        if (ep.hostnames.length) html += gridRow("Hostnames", ep.hostnames.join(", "));
        if (ep.sysmon_computer_name) html += gridRow("Computer Name", ep.sysmon_computer_name);
        if (ep.mac_addresses.length) html += gridRow("MAC Addresses", ep.mac_addresses.join(", "));
        if (ep.os_info.length) html += gridRow("OS Info", ep.os_info.join(", "));
        html += gridRow("Internal", ep.is_internal === true ? "Yes" : ep.is_internal === false ? "No" : "Unknown");
        html += gridRow("First Seen", formatTime(ep.first_seen));
        html += gridRow("Last Seen", formatTime(ep.last_seen));
        html += gridRow("Total Connections", ep.connection_count.toLocaleString());
        html += gridRow("Bytes Sent", formatBytes(ep.total_bytes_sent));
        html += gridRow("Bytes Received", formatBytes(ep.total_bytes_received));
        html += `</div></div>`;

        // ── Open Ports ──
        if (Object.keys(ep.open_ports).length) {
            html += `<div class="detail-section"><h4>Open Ports (${Object.keys(ep.open_ports).length})</h4><div>`;
            const entries = Object.entries(ep.open_ports).sort((a, b) => parseInt(a[0]) - parseInt(b[0]));
            for (const [port, services] of entries) {
                html += `<span class="port-badge">${port}/${services.join(",")}</span> `;
            }
            html += `</div></div>`;
        }

        // ── Services ──
        if (ep.services.length) {
            html += `<div class="detail-section"><h4>Services (${ep.services.length})</h4>
                <ul class="detail-list">${ep.services.map(s => `<li>${escapeHtml(s)}</li>`).join("")}</ul></div>`;
        }

        // ── Protocols ──
        if (ep.protocols && ep.protocols.length) {
            html += `<div class="detail-section"><h4>Protocols</h4>
                <ul class="detail-list">${ep.protocols.map(p => `<li>${escapeHtml(p)}</li>`).join("")}</ul></div>`;
        }

        // ── User Agents ──
        if (ep.user_agents && ep.user_agents.length) {
            html += `<div class="detail-section"><h4>User Agents</h4>
                <ul class="detail-list">${ep.user_agents.map(u => `<li>${escapeHtml(u)}</li>`).join("")}</ul></div>`;
        }

        // ── DNS Queries ──
        if (ep.dns_queries.length) {
            html += `<div class="detail-section"><h4>DNS Queries (${ep.dns_queries.length})</h4>
                <ul class="detail-list">${ep.dns_queries.slice(0, 50).map(d => `<li>${escapeHtml(d)}</li>`).join("")}</ul></div>`;
        }

        // ── Processes (from Sysmon) ──
        if (ep.processes.length) {
            html += `<div class="detail-section"><h4>Processes (${ep.processes.length})</h4>`;
            html += `<table class="detail-table"><thead><tr>
                <th>Name</th><th>User</th><th>Parent</th><th>Destination</th>
            </tr></thead><tbody>`;
            for (const p of ep.processes.slice(0, 50)) {
                html += `<tr>
                    <td title="${escapeHtml(p.exe || "")}">${escapeHtml(p.name || "")}</td>
                    <td>${escapeHtml(p.user || "")}</td>
                    <td>${escapeHtml(p.parent || "")}</td>
                    <td>${escapeHtml(p.dst || "")}</td>
                </tr>`;
            }
            html += `</tbody></table></div>`;
        }

        // ── Certificates ──
        if (ep.certificates.length) {
            html += `<div class="detail-section"><h4>Certificates (${ep.certificates.length})</h4>`;
            html += `<table class="detail-table"><thead><tr>
                <th>Subject</th><th>Issuer</th><th>Server Name</th>
            </tr></thead><tbody>`;
            for (const c of ep.certificates.slice(0, 20)) {
                html += `<tr>
                    <td title="${escapeHtml(c.subject || "")}">${escapeHtml(truncate(c.subject || "", 30))}</td>
                    <td title="${escapeHtml(c.issuer || "")}">${escapeHtml(truncate(c.issuer || "", 30))}</td>
                    <td>${escapeHtml(c.server_name || c.san || "")}</td>
                </tr>`;
            }
            html += `</tbody></table></div>`;
        }

        // ── Connections ──
        if (ep.connections && ep.connections.length) {
            html += `<div class="detail-section"><h4>Connections (${ep.connections.length})</h4>`;
            html += `<table class="detail-table"><thead><tr>
                <th>Direction</th><th>Remote</th><th>Port</th><th>Service</th><th>Count</th><th>Bytes</th>
            </tr></thead><tbody>`;
            const maxBytes = Math.max(...ep.connections.map(c => c.total_bytes || 1));
            for (const c of ep.connections.slice(0, 100)) {
                const dir = c.src_ip === ep.ip ? "&rarr;" : "&larr;";
                const remote = c.src_ip === ep.ip ? c.dst_ip : c.src_ip;
                const barWidth = Math.max(2, (c.total_bytes / maxBytes) * 60);
                html += `<tr>
                    <td>${dir}</td>
                    <td class="clickable-ip" data-ip="${remote}" style="cursor:pointer;color:var(--accent-cyan)">${remote}</td>
                    <td>${c.dst_port}</td>
                    <td>${escapeHtml(c.service || c.proto)}</td>
                    <td>${c.count}</td>
                    <td><div class="bytes-bar" style="width:${barWidth}px" title="${formatBytes(c.total_bytes)}"></div>${formatBytes(c.total_bytes)}</td>
                </tr>`;
            }
            html += `</tbody></table></div>`;
        }

        container.innerHTML = html;

        // Add click handlers for IPs in the connection table
        container.querySelectorAll(".clickable-ip").forEach(el => {
            el.addEventListener("click", () => selectNode(el.dataset.ip));
        });
    }

    // ── Controls ───────────────────────────────────────────────────
    function initControls() {
        let searchTimeout;
        document.getElementById("search-input").addEventListener("input", (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => filterAndRefresh(), 300);
        });

        document.getElementById("filter-internal").addEventListener("change", filterAndRefresh);
        document.getElementById("filter-external").addEventListener("change", filterAndRefresh);

        document.getElementById("btn-refresh").addEventListener("click", fetchGraph);

        document.getElementById("btn-fit").addEventListener("click", () => {
            const width = svg.node().parentElement.clientWidth;
            const height = svg.node().parentElement.clientHeight;
            svg.transition().duration(500).call(
                zoom.transform,
                d3.zoomIdentity.translate(width / 2, height / 2).scale(0.8).translate(-width / 2, -height / 2)
            );
        });

        document.getElementById("detail-close").addEventListener("click", () => {
            document.getElementById("detail-panel").classList.add("hidden");
            selectedNodeId = null;
            nodeGroup.selectAll("g.node").select("circle")
                .attr("stroke", d => d3.color(nodeColor(d)).brighter(0.5))
                .attr("stroke-width", 2);
        });
    }

    function filterAndRefresh() {
        const search = document.getElementById("search-input").value.toLowerCase();
        const internalOnly = document.getElementById("filter-internal").checked;
        const externalOnly = document.getElementById("filter-external").checked;

        let filtered = { ...graphData };
        let nodeIds = new Set(filtered.nodes.map(n => n.id));

        if (search || internalOnly || externalOnly) {
            filtered.nodes = filtered.nodes.filter(n => {
                if (internalOnly && n.is_internal !== true) return false;
                if (externalOnly && n.is_internal !== false) return false;
                if (search) {
                    return n.ip.toLowerCase().includes(search)
                        || n.label.toLowerCase().includes(search)
                        || n.services.some(s => s.toLowerCase().includes(search));
                }
                return true;
            });
            nodeIds = new Set(filtered.nodes.map(n => n.id));
            filtered.edges = filtered.edges.filter(e => {
                const src = typeof e.source === "object" ? e.source.id : e.source;
                const tgt = typeof e.target === "object" ? e.target.id : e.target;
                return nodeIds.has(src) && nodeIds.has(tgt);
            });
        }

        updateGraph(filtered);
    }

    // ── Data fetching ──────────────────────────────────────────────
    async function fetchGraph() {
        try {
            const resp = await fetch("/api/graph");
            const data = await resp.json();
            currentVersion = data.version;
            updateGraph(data);
            updateStats(data);
        } catch (e) {
            console.error("Failed to fetch graph:", e);
        }
    }

    function updateStats(data) {
        const stats = data;
        document.getElementById("stat-endpoints").textContent = stats.endpoint_count || stats.total_endpoints || 0;
        document.getElementById("stat-internal").textContent = stats.internal_endpoints || 0;
        document.getElementById("stat-external").textContent = stats.external_endpoints || 0;
        document.getElementById("stat-connections").textContent = stats.connection_count || stats.total_connections || 0;
        document.getElementById("stat-dns").textContent = stats.total_dns_domains || 0;
        if (stats.last_updated) {
            document.getElementById("last-updated").textContent = "Updated: " + formatTime(stats.last_updated);
        }
    }

    // ── WebSocket ──────────────────────────────────────────────────
    function connectWebSocket() {
        const proto = location.protocol === "https:" ? "wss" : "ws";
        ws = new WebSocket(`${proto}://${location.host}/ws`);
        const statusEl = document.getElementById("connection-status");
        const statusText = statusEl.querySelector(".status-text");

        ws.onopen = () => {
            statusEl.className = "status-indicator connected";
            statusText.textContent = "Live";
        };

        ws.onclose = () => {
            statusEl.className = "status-indicator disconnected";
            statusText.textContent = "Disconnected";
            // Reconnect after 5s
            setTimeout(connectWebSocket, 5000);
        };

        ws.onerror = () => {
            statusEl.className = "status-indicator disconnected";
            statusText.textContent = "Error";
        };

        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            if (msg.type === "init" || msg.type === "update") {
                updateStats(msg.stats);
                if (msg.version > currentVersion) {
                    currentVersion = msg.version;
                    fetchGraph();
                }
            } else if (msg.type === "graph") {
                currentVersion = msg.data.version;
                updateGraph(msg.data);
                updateStats(msg.data);
            }
        };

        // Keep alive
        setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send("ping");
            }
        }, 30000);
    }

    // ── Utilities ──────────────────────────────────────────────────
    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 B";
        const units = ["B", "KB", "MB", "GB", "TB"];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
    }

    function formatTime(ts) {
        if (!ts) return "-";
        try {
            const d = new Date(ts);
            return d.toLocaleString();
        } catch { return ts; }
    }

    function truncate(str, max) {
        if (!str) return "";
        return str.length > max ? str.substring(0, max) + "..." : str;
    }

    function escapeHtml(str) {
        if (!str) return "";
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    function gridRow(label, value) {
        return `<span class="label">${label}</span><span class="value">${escapeHtml(String(value || "-"))}</span>`;
    }
})();
