"""
Security Event Correlation Engine

Workflow
--------
1. Fetch Cybereason EDR events from ArcSight ESM
   (filtered by deviceVendor = 'Cybereason' within a configurable lookback window).
2. For each EDR event, extract indicators:
     - sourceAddress      → source IP
     - destinationAddress → destination IP
     - deviceHostName     → hostname
     - endTime            → event timestamp
3. Query ArcSight ESM for ALL events in the ±15-minute window around
   that timestamp, filtered by each extracted indicator.
4. De-duplicate and aggregate the matched context events.
5. Return a structured CorrelationReport.
"""

from __future__ import annotations

import datetime
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from arcsight_client import ArcSightClient, _ms_to_iso

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class CorrelationResult:
    """Correlation result for a single EDR event."""

    # EDR seed event (from ArcSight, device = Cybereason)
    edr_event_id: str
    edr_event_name: str
    edr_severity: str
    edr_timestamp_ms: int
    edr_timestamp_iso: str
    edr_device_vendor: str
    edr_device_product: str

    # Extracted indicators
    source_ips: list[str]
    dest_ips: list[str]
    hostnames: list[str]

    # Time window used for the context query
    window_start_ms: int
    window_end_ms: int
    window_start_iso: str
    window_end_iso: str

    # Correlated ArcSight context events (excluding the EDR event itself)
    correlated_events: list[dict[str, Any]] = field(default_factory=list)
    correlated_event_count: int = 0

    # Error if something went wrong
    error: Optional[str] = None


@dataclass
class CorrelationReport:
    """Full correlation report across all processed EDR events."""

    generated_at: str
    window_minutes: int
    edr_vendor: str
    lookback_hours: int
    total_edr_events: int
    total_correlated_events: int
    results: list[CorrelationResult]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SecurityEventCorrelator:
    """
    Correlates Cybereason EDR events stored in ArcSight ESM with surrounding
    security events from all other sources in the same ArcSight ESM.

    Both the seed (EDR) events and the context events are fetched from a
    single ArcSight ESM instance.
    """

    def __init__(
        self,
        as_client: ArcSightClient,
        window_minutes: int = 15,
        max_correlated_results: int = 200,
    ) -> None:
        self.as_client = as_client
        self.window_ms = window_minutes * 60 * 1000
        self.window_minutes = window_minutes
        self.max_correlated_results = max_correlated_results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        lookback_hours: int = 24,
        edr_event_limit: int = 25,
    ) -> CorrelationReport:
        """
        Execute the full correlation pipeline.

        Parameters
        ----------
        lookback_hours : int
            How many hours back to look for Cybereason EDR events in ArcSight.
            The query window is [now - lookback_hours, now].
        edr_event_limit : int
            Maximum number of EDR events to process in one run.

        Returns
        -------
        CorrelationReport
        """
        now_ms = _now_ms()
        lookback_ms = now_ms - lookback_hours * 3600 * 1000

        logger.info(
            "Starting correlation run: lookback=%dh, window=±%dmin, limit=%d",
            lookback_hours,
            self.window_minutes,
            edr_event_limit,
        )
        logger.info(
            "EDR event search window: %s – %s",
            _ms_to_iso(lookback_ms),
            _ms_to_iso(now_ms),
        )

        # Step 1: Fetch Cybereason EDR events from ArcSight
        edr_events = self.as_client.get_edr_events(
            start_time_ms=lookback_ms,
            end_time_ms=now_ms,
            max_results=edr_event_limit,
        )
        logger.info("Processing %d EDR events", len(edr_events))

        results: list[CorrelationResult] = []
        for edr_event in edr_events:
            result = self._correlate_edr_event(edr_event)
            results.append(result)

        total_correlated = sum(r.correlated_event_count for r in results)
        report = CorrelationReport(
            generated_at=datetime.datetime.now(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            window_minutes=self.window_minutes,
            edr_vendor=self.as_client.edr_vendor,
            lookback_hours=lookback_hours,
            total_edr_events=len(results),
            total_correlated_events=total_correlated,
            results=results,
        )
        logger.info(
            "Correlation complete: %d EDR events processed, "
            "%d context events matched",
            report.total_edr_events,
            report.total_correlated_events,
        )
        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_indicators(
        self, edr_event: dict[str, Any]
    ) -> tuple[list[str], list[str], list[str]]:
        """
        Extract source IPs, destination IPs, and hostnames from an ArcSight
        EDR event record.

        ArcSight CEF field mapping
        --------------------------
        sourceAddress       → source IP
        destinationAddress  → destination IP
        deviceHostName      → hostname of the device reporting the event
        sourceHostName      → hostname resolved from source IP (fallback)
        destinationHostName → hostname resolved from destination IP (fallback)
        """
        source_ips: list[str] = []
        dest_ips: list[str] = []
        hostnames: list[str] = []

        def _add_unique(lst: list[str], value: Any) -> None:
            v = str(value).strip() if value else ""
            if v and v not in lst:
                lst.append(v)

        _add_unique(source_ips, edr_event.get("sourceAddress"))
        _add_unique(dest_ips, edr_event.get("destinationAddress"))
        _add_unique(hostnames, edr_event.get("deviceHostName"))
        _add_unique(hostnames, edr_event.get("sourceHostName"))
        _add_unique(hostnames, edr_event.get("destinationHostName"))

        return source_ips, dest_ips, hostnames

    def _correlate_edr_event(
        self, edr_event: dict[str, Any]
    ) -> CorrelationResult:
        """
        For one EDR event, extract indicators and query ArcSight for
        surrounding events in the ±window time range.
        """
        edr_id = str(
            edr_event.get("eventId")
            or edr_event.get("id")
            or edr_event.get("arcsightEventId")
            or id(edr_event)
        )
        edr_name = (
            edr_event.get("name") or edr_event.get("message") or ""
        )
        edr_severity = str(edr_event.get("severity", ""))
        edr_vendor = str(edr_event.get("deviceVendor", ""))
        edr_product = str(edr_event.get("deviceProduct", ""))

        # Timestamp: prefer endTime, fall back to startTime
        ts_ms = int(
            edr_event.get("endTime") or edr_event.get("startTime") or 0
        )

        source_ips, dest_ips, hostnames = self._extract_indicators(edr_event)

        if not ts_ms:
            return CorrelationResult(
                edr_event_id=edr_id,
                edr_event_name=edr_name,
                edr_severity=edr_severity,
                edr_timestamp_ms=0,
                edr_timestamp_iso="",
                edr_device_vendor=edr_vendor,
                edr_device_product=edr_product,
                source_ips=source_ips,
                dest_ips=dest_ips,
                hostnames=hostnames,
                window_start_ms=0,
                window_end_ms=0,
                window_start_iso="",
                window_end_iso="",
                error="No timestamp on EDR event",
            )

        if not any([source_ips, dest_ips, hostnames]):
            return CorrelationResult(
                edr_event_id=edr_id,
                edr_event_name=edr_name,
                edr_severity=edr_severity,
                edr_timestamp_ms=ts_ms,
                edr_timestamp_iso=_ms_to_iso(ts_ms),
                edr_device_vendor=edr_vendor,
                edr_device_product=edr_product,
                source_ips=[],
                dest_ips=[],
                hostnames=[],
                window_start_ms=0,
                window_end_ms=0,
                window_start_iso="",
                window_end_iso="",
                error="No source IP / destination IP / hostname in EDR event",
            )

        # Compute ±window
        window_start = ts_ms - self.window_ms
        window_end = ts_ms + self.window_ms

        logger.info(
            "EDR event %s (%s) — window %s – %s  "
            "src_ips=%s dst_ips=%s hosts=%s",
            edr_id,
            edr_name,
            _ms_to_iso(window_start),
            _ms_to_iso(window_end),
            source_ips,
            dest_ips,
            hostnames,
        )

        # Query ArcSight for each indicator; de-duplicate by eventId
        correlated: list[dict[str, Any]] = []
        seen_ids: set[str] = {edr_id}  # exclude the seed event itself

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
                    correlated.append(evt)

        for src_ip in source_ips:
            try:
                _add_events(
                    self.as_client.search_events(
                        start_time_ms=window_start,
                        end_time_ms=window_end,
                        source_address=src_ip,
                        max_results=self.max_correlated_results,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "ArcSight query failed (src_ip=%s): %s", src_ip, exc
                )

        for dst_ip in dest_ips:
            try:
                _add_events(
                    self.as_client.search_events(
                        start_time_ms=window_start,
                        end_time_ms=window_end,
                        destination_address=dst_ip,
                        max_results=self.max_correlated_results,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "ArcSight query failed (dst_ip=%s): %s", dst_ip, exc
                )

        for hostname in hostnames:
            try:
                _add_events(
                    self.as_client.search_events(
                        start_time_ms=window_start,
                        end_time_ms=window_end,
                        device_hostname=hostname,
                        max_results=self.max_correlated_results,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "ArcSight query failed (hostname=%s): %s", hostname, exc
                )

        # Sort correlated events by time ascending
        correlated.sort(
            key=lambda e: int(e.get("endTime") or e.get("startTime") or 0)
        )

        logger.info(
            "EDR event %s: %d correlated context events found",
            edr_id,
            len(correlated),
        )

        return CorrelationResult(
            edr_event_id=edr_id,
            edr_event_name=edr_name,
            edr_severity=edr_severity,
            edr_timestamp_ms=ts_ms,
            edr_timestamp_iso=_ms_to_iso(ts_ms),
            edr_device_vendor=edr_vendor,
            edr_device_product=edr_product,
            source_ips=source_ips,
            dest_ips=dest_ips,
            hostnames=hostnames,
            window_start_ms=window_start,
            window_end_ms=window_end,
            window_start_iso=_ms_to_iso(window_start),
            window_end_iso=_ms_to_iso(window_end),
            correlated_events=correlated,
            correlated_event_count=len(correlated),
        )


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _now_ms() -> int:
    """Return current UTC time as epoch milliseconds."""
    return int(
        datetime.datetime.now(datetime.timezone.utc).timestamp() * 1000
    )
