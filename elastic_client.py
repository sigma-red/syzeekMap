"""Elasticsearch client wrapper for querying Security Onion indices."""

from __future__ import annotations

import logging
from typing import Generator

from elasticsearch import Elasticsearch

from config import Config

logger = logging.getLogger(__name__)


class ElasticClient:
    """Handles Elasticsearch connectivity and queries against Security Onion."""

    def __init__(self):
        self.es = Elasticsearch(
            Config.ES_HOST,
            basic_auth=(Config.ES_USERNAME, Config.ES_PASSWORD),
            verify_certs=Config.ES_VERIFY_CERTS,
            request_timeout=60,
        )
        self._last_zeek_timestamp: str | None = None
        self._last_sysmon_timestamp: str | None = None

    def test_connection(self) -> bool:
        try:
            info = self.es.info()
            logger.info("Connected to Elasticsearch: %s", info.get("version", {}).get("number"))
            return True
        except Exception as e:
            logger.error("Failed to connect to Elasticsearch: %s", e)
            return False

    def _scroll_query(
        self, index: str, query: dict, sort_field: str = "@timestamp", size: int = 5000
    ) -> Generator[dict, None, None]:
        """Execute a search with search_after pagination."""
        body = {
            "query": query,
            "sort": [{sort_field: "asc"}, {"_id": "asc"}],
            "size": size,
        }
        search_after = None
        total_yielded = 0
        max_results = 50000  # Safety cap per poll cycle

        while total_yielded < max_results:
            if search_after:
                body["search_after"] = search_after
            try:
                resp = self.es.search(index=index, body=body)
            except Exception as e:
                logger.error("Elasticsearch query error on %s: %s", index, e)
                break

            hits = resp.get("hits", {}).get("hits", [])
            if not hits:
                break

            for hit in hits:
                yield hit["_source"]
                total_yielded += 1

            search_after = hits[-1]["sort"]

        if total_yielded >= max_results:
            logger.warning("Hit max results cap (%d) for index %s", max_results, index)

    # ------------------------------------------------------------------
    # Zeek queries
    # ------------------------------------------------------------------

    def fetch_zeek_conn(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        """Fetch Zeek conn.log entries."""
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "conn"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_dns(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "dns"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_ssl(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "ssl"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_http(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "http"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_x509(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "x509"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_software(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "software"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_kerberos(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "kerberos"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    # ------------------------------------------------------------------
    # Zeek ICS/OT protocol queries
    # ------------------------------------------------------------------

    def fetch_zeek_modbus(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "modbus"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_dnp3(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "dnp3"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_s7comm(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "s7comm"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_bacnet(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "bacnet"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_enip(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        """EtherNet/IP (CIP) protocol."""
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "enip"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    def fetch_zeek_cip(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        """CIP (Common Industrial Protocol) over EtherNet/IP."""
        query = self._time_range_query(since, until, extra_filter={"term": {"event.dataset": "cip"}})
        yield from self._scroll_query(Config.ZEEK_INDEX_PATTERN, query)

    # ------------------------------------------------------------------
    # Sysmon queries
    # ------------------------------------------------------------------

    def fetch_sysmon_network(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        """Sysmon Event ID 3 - Network connection."""
        query = self._time_range_query(
            since, until, extra_filter={"term": {"winlog.event_id": 3}}
        )
        yield from self._scroll_query(Config.SYSMON_INDEX_PATTERN, query)

    def fetch_sysmon_process_create(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        """Sysmon Event ID 1 - Process creation."""
        query = self._time_range_query(
            since, until, extra_filter={"term": {"winlog.event_id": 1}}
        )
        yield from self._scroll_query(Config.SYSMON_INDEX_PATTERN, query)

    def fetch_sysmon_dns(self, since: str | None = None, until: str | None = None) -> Generator[dict, None, None]:
        """Sysmon Event ID 22 - DNS query."""
        query = self._time_range_query(
            since, until, extra_filter={"term": {"winlog.event_id": 22}}
        )
        yield from self._scroll_query(Config.SYSMON_INDEX_PATTERN, query)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _time_range_query(
        since: str | None,
        until: str | None = None,
        extra_filter: dict | None = None,
    ) -> dict:
        filters: list[dict] = []
        if since or until:
            ts_range: dict = {}
            if since:
                ts_range["gt"] = since
            if until:
                ts_range["lte"] = until
            filters.append({"range": {"@timestamp": ts_range}})
        if extra_filter:
            filters.append(extra_filter)
        if filters:
            return {"bool": {"filter": filters}}
        return {"match_all": {}}

    @staticmethod
    def _safe_get(doc: dict, *keys, default=None):
        """Safely traverse nested dict keys."""
        current = doc
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key, default)
            else:
                return default
        return current
