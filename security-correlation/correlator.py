"""
Security Event Correlation Engine

Workflow
--------
1. Fetch active Cybereason EDR MalOps.
2. For each MalOp, extract indicators:
     - Source IP addresses   (from affected machines)
     - Destination IP addresses (from MalOp IOCs)
     - Hostnames             (from affected machines)
     - Event timestamp       (lastUpdateTime / creationTime)
3. Query ArcSight ESM for all events in the ±15-minute window around
   the MalOp timestamp, filtered by each extracted indicator.
4. De-duplicate and aggregate the matched ArcSight events.
5. Return a structured CorrelationReport.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from arcsight_client import ArcSightClient, _ms_to_iso
from cybereason_client import CybereasonClient

logger = logging.getLogger(__name__)

# ±15 minutes expressed in milliseconds
_WINDOW_MS = 15 * 60 * 1000


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CorrelationResult:
    """Correlation result for a single MalOp."""

    malop_guid: str
    malop_name: str
    malop_severity: str
    malop_status: str
    malop_timestamp_ms: int
    malop_timestamp_iso: str

    # Extracted indicators
    hostnames: list[str]
    source_ips: list[str]
    dest_ips: list[str]

    # Time window used for ArcSight query
    window_start_ms: int
    window_end_ms: int
    window_start_iso: str
    window_end_iso: str

    # Matched ArcSight events
    arcsight_events: list[dict[str, Any]] = field(default_factory=list)
    arcsight_event_count: int = 0

    # Error if something went wrong
    error: Optional[str] = None


@dataclass
class CorrelationReport:
    """Full correlation report across all processed MalOps."""

    generated_at: str
    window_minutes: int
    total_malops: int
    total_arcsight_events: int
    results: list[CorrelationResult]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SecurityEventCorrelator:
    """
    Orchestrates the cross-system correlation between Cybereason EDR events
    and ArcSight ESM events.
    """

    def __init__(
        self,
        cr_client: CybereasonClient,
        as_client: ArcSightClient,
        window_minutes: int = 15,
        enrich_machine_ips: bool = True,
        max_arcsight_results: int = 200,
    ) -> None:
        self.cr = cr_client
        self.as_client = as_client
        self.window_ms = window_minutes * 60 * 1000
        self.window_minutes = window_minutes
        self.enrich_machine_ips = enrich_machine_ips
        self.max_arcsight_results = max_arcsight_results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        status_filter: Optional[list[str]] = None,
        malop_limit: int = 25,
    ) -> CorrelationReport:
        """
        Execute the full correlation pipeline.

        Parameters
        ----------
        status_filter : list[str]
            Cybereason investigationStatus values to process.
            Defaults to ["TODO"].
        malop_limit : int
            Maximum number of MalOps to process in one run.

        Returns
        -------
        CorrelationReport
        """
        logger.info(
            "Starting correlation run (status=%s, limit=%d)",
            status_filter or ["TODO"],
            malop_limit,
        )

        malops = self.cr.get_malops(
            status_filter=status_filter or ["TODO"],
            limit=malop_limit,
        )
        logger.info("Fetched %d Cybereason MalOps", len(malops))

        results: list[CorrelationResult] = []
        for malop in malops:
            result = self._correlate_malop(malop)
            results.append(result)

        total_events = sum(r.arcsight_event_count for r in results)
        report = CorrelationReport(
            generated_at=datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            window_minutes=self.window_minutes,
            total_malops=len(results),
            total_arcsight_events=total_events,
            results=results,
        )
        logger.info(
            "Correlation complete: %d MalOps, %d ArcSight events matched",
            report.total_malops,
            report.total_arcsight_events,
        )
        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _correlate_malop(self, malop: dict[str, Any]) -> CorrelationResult:
        """Run correlation for a single MalOp."""
        malop_guid = malop.get("guid", "unknown")
        malop_name = malop.get("displayName", "")
        malop_severity = malop.get("severity", "")
        malop_status = malop.get("investigationStatus", "")

        # 1. Extract indicators
        try:
            indicators = self.cr.extract_indicators(
                malop, enrich_ips=self.enrich_machine_ips
            )
        except Exception as exc:
            logger.exception("Indicator extraction failed for MalOp %s", malop_guid)
            ts_ms = int(
                malop.get("lastUpdateTime") or malop.get("creationTime") or 0
            )
            return CorrelationResult(
                malop_guid=malop_guid,
                malop_name=malop_name,
                malop_severity=malop_severity,
                malop_status=malop_status,
                malop_timestamp_ms=ts_ms,
                malop_timestamp_iso=_ms_to_iso(ts_ms) if ts_ms else "",
                hostnames=[],
                source_ips=[],
                dest_ips=[],
                window_start_ms=0,
                window_end_ms=0,
                window_start_iso="",
                window_end_iso="",
                error=f"Indicator extraction error: {exc}",
            )

        ts_ms = indicators["timestamp_ms"]
        hostnames = indicators["hostnames"]
        source_ips = indicators["source_ips"]
        dest_ips = indicators["dest_ips"]

        if not ts_ms:
            return CorrelationResult(
                malop_guid=malop_guid,
                malop_name=malop_name,
                malop_severity=malop_severity,
                malop_status=malop_status,
                malop_timestamp_ms=0,
                malop_timestamp_iso="",
                hostnames=hostnames,
                source_ips=source_ips,
                dest_ips=dest_ips,
                window_start_ms=0,
                window_end_ms=0,
                window_start_iso="",
                window_end_iso="",
                error="No timestamp available on MalOp",
            )

        # 2. Compute ±15-minute window
        window_start = ts_ms - self.window_ms
        window_end = ts_ms + self.window_ms

        logger.info(
            "Correlating MalOp %s (%s) — window %s – %s",
            malop_guid,
            malop_name,
            _ms_to_iso(window_start),
            _ms_to_iso(window_end),
        )

        # 3. Query ArcSight for each indicator (deduplicate by event ID)
        arcsight_events: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        def _add_events(events: list[dict[str, Any]]) -> None:
            for evt in events:
                eid = str(
                    evt.get("eventId")
                    or evt.get("id")
                    or evt.get("arcsightEventId")
                    or id(evt)
                )
                if eid not in seen_ids:
                    seen_ids.add(eid)
                    arcsight_events.append(evt)

        for src_ip in source_ips:
            try:
                events = self.as_client.search_events(
                    start_time_ms=window_start,
                    end_time_ms=window_end,
                    source_address=src_ip,
                    max_results=self.max_arcsight_results,
                )
                _add_events(events)
            except Exception as exc:
                logger.warning(
                    "ArcSight query failed (src_ip=%s): %s", src_ip, exc
                )

        for dst_ip in dest_ips:
            try:
                events = self.as_client.search_events(
                    start_time_ms=window_start,
                    end_time_ms=window_end,
                    destination_address=dst_ip,
                    max_results=self.max_arcsight_results,
                )
                _add_events(events)
            except Exception as exc:
                logger.warning(
                    "ArcSight query failed (dst_ip=%s): %s", dst_ip, exc
                )

        for hostname in hostnames:
            try:
                events = self.as_client.search_events(
                    start_time_ms=window_start,
                    end_time_ms=window_end,
                    device_hostname=hostname,
                    max_results=self.max_arcsight_results,
                )
                _add_events(events)
            except Exception as exc:
                logger.warning(
                    "ArcSight query failed (hostname=%s): %s", hostname, exc
                )

        # 4. Sort by event time (ascending)
        arcsight_events.sort(
            key=lambda e: int(e.get("endTime") or e.get("startTime") or 0)
        )

        logger.info(
            "MalOp %s: %d unique ArcSight events correlated",
            malop_guid,
            len(arcsight_events),
        )

        return CorrelationResult(
            malop_guid=malop_guid,
            malop_name=malop_name,
            malop_severity=malop_severity,
            malop_status=malop_status,
            malop_timestamp_ms=ts_ms,
            malop_timestamp_iso=_ms_to_iso(ts_ms),
            hostnames=hostnames,
            source_ips=source_ips,
            dest_ips=dest_ips,
            window_start_ms=window_start,
            window_end_ms=window_end,
            window_start_iso=_ms_to_iso(window_start),
            window_end_iso=_ms_to_iso(window_end),
            arcsight_events=arcsight_events,
            arcsight_event_count=len(arcsight_events),
        )
