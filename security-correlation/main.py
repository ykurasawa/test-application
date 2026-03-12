"""
Security Event Correlation Application
ArcSight ESM – Cybereason EDR 相関分析

Both the Cybereason EDR events (seed) and the surrounding context events are
fetched from ArcSight ESM.  No direct connection to the Cybereason platform
is required.

Usage
-----
  # Run with environment variables:
  python main.py

  # Override defaults via CLI flags:
  python main.py --lookback 48 --limit 50 --window 15 --output report.json

Environment Variables
---------------------
  ARCSIGHT_URL             ArcSight ESM base URL (e.g. https://host:8443)
  ARCSIGHT_USERNAME        ArcSight username
  ARCSIGHT_PASSWORD        ArcSight password
  ARCSIGHT_VERIFY_SSL      "false" to skip TLS check (default: true)
  ARCSIGHT_QUERY_VIEW_URI  Query View resource URI (optional)
  ARCSIGHT_EDR_VENDOR      deviceVendor value for EDR events (default: Cybereason)
  ARCSIGHT_EDR_PRODUCT     deviceProduct value for EDR events (optional)

  CORRELATION_LOOKBACK_HOURS  Hours back to search for EDR events (default: 24)
  CORRELATION_EDR_LIMIT       Max EDR events to process per run (default: 25)
  CORRELATION_WINDOW_MIN      Context window in minutes (default: 15)
  CORRELATION_OUTPUT_FILE     Output JSON path (default: correlation_report.json)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from arcsight_client import ArcSightClient
from correlator import CorrelationReport, CorrelationResult, SecurityEventCorrelator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("correlation-app")

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

load_dotenv()


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_bool(key: str, default: bool = True) -> bool:
    val = os.environ.get(key, "")
    return val.lower() not in ("false", "0", "no") if val else default


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _report_to_dict(report: CorrelationReport) -> dict:
    """Convert the report dataclass tree to a JSON-serialisable dict."""

    def result_to_dict(r: CorrelationResult) -> dict:
        return {
            "edr_event_id": r.edr_event_id,
            "edr_event_name": r.edr_event_name,
            "edr_severity": r.edr_severity,
            "edr_device_vendor": r.edr_device_vendor,
            "edr_device_product": r.edr_device_product,
            "edr_timestamp_iso": r.edr_timestamp_iso,
            "indicators": {
                "source_ips": r.source_ips,
                "dest_ips": r.dest_ips,
                "hostnames": r.hostnames,
            },
            "time_window": {
                "start_iso": r.window_start_iso,
                "end_iso": r.window_end_iso,
                "window_minutes": report.window_minutes,
            },
            "correlated_event_count": r.correlated_event_count,
            "correlated_events": r.correlated_events,
            "error": r.error,
        }

    return {
        "generated_at": report.generated_at,
        "edr_vendor": report.edr_vendor,
        "lookback_hours": report.lookback_hours,
        "window_minutes": report.window_minutes,
        "summary": {
            "total_edr_events": report.total_edr_events,
            "total_correlated_events": report.total_correlated_events,
            "edr_events_with_matches": sum(
                1 for r in report.results if r.correlated_event_count > 0
            ),
            "edr_events_with_errors": sum(
                1 for r in report.results if r.error
            ),
        },
        "results": [result_to_dict(r) for r in report.results],
    }


def _print_summary(report: CorrelationReport) -> None:
    """Print a human-readable summary to stdout."""
    sep = "=" * 72

    print(sep)
    print("  SECURITY EVENT CORRELATION REPORT")
    print(f"  Generated  : {report.generated_at}")
    print(f"  EDR Vendor : {report.edr_vendor}")
    print(f"  Lookback   : {report.lookback_hours} hours")
    print(f"  Window     : ±{report.window_minutes} minutes")
    print(sep)
    print(f"  EDR events processed    : {report.total_edr_events}")
    print(f"  Context events matched  : {report.total_correlated_events}")
    matched = sum(1 for r in report.results if r.correlated_event_count > 0)
    print(f"  EDR events with hits    : {matched}")
    print(sep)

    for idx, result in enumerate(report.results, start=1):
        print(
            f"\n[{idx}/{report.total_edr_events}] "
            f"{result.edr_event_name or result.edr_event_id}"
        )
        print(f"  Event ID   : {result.edr_event_id}")
        print(f"  Vendor     : {result.edr_device_vendor} / {result.edr_device_product}")
        print(f"  Severity   : {result.edr_severity}")
        print(f"  Timestamp  : {result.edr_timestamp_iso}")
        print(
            f"  Window     : {result.window_start_iso} – {result.window_end_iso}"
        )
        print(f"  Source IPs : {', '.join(result.source_ips) or '(none)'}")
        print(f"  Dest IPs   : {', '.join(result.dest_ips) or '(none)'}")
        print(f"  Hostnames  : {', '.join(result.hostnames) or '(none)'}")

        if result.error:
            print(f"  ERROR      : {result.error}")
        else:
            print(
                f"  Correlated : {result.correlated_event_count} context events"
            )
            for evt in result.correlated_events[:5]:
                evt_time = evt.get("endTime") or evt.get("startTime") or ""
                evt_name = evt.get("name") or evt.get("message") or "(unnamed)"
                evt_src = evt.get("sourceAddress", "")
                evt_dst = evt.get("destinationAddress", "")
                evt_sev = evt.get("severity", "")
                evt_vendor = evt.get("deviceVendor", "")
                print(
                    f"    • [{evt_time}] {evt_name}"
                    f"  src={evt_src} dst={evt_dst}"
                    f"  sev={evt_sev} vendor={evt_vendor}"
                )
            if result.correlated_event_count > 5:
                print(
                    f"    … and {result.correlated_event_count - 5} more "
                    "(see JSON output for full list)"
                )

    print(f"\n{sep}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="correlation-app",
        description=(
            "Fetch Cybereason EDR events from ArcSight ESM and correlate "
            "with surrounding events in a ±window time range."
        ),
    )
    parser.add_argument(
        "--lookback",
        type=int,
        default=None,
        metavar="HOURS",
        help=(
            "How many hours back to search for EDR events in ArcSight. "
            "Default: CORRELATION_LOOKBACK_HOURS env var, or 24."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Max number of EDR events to process (default 25).",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=None,
        metavar="MINUTES",
        help="Context time window in minutes (default 15).",
    )
    parser.add_argument(
        "--edr-vendor",
        default=None,
        metavar="VENDOR",
        help=(
            "ArcSight deviceVendor value to identify EDR events. "
            "Default: ARCSIGHT_EDR_VENDOR env var, or 'Cybereason'."
        ),
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Path to write the JSON report (default: correlation_report.json).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration and connectivity only; do not run correlation.",
    )
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    # --- ArcSight config ---
    as_url = _env("ARCSIGHT_URL")
    as_user = _env("ARCSIGHT_USERNAME")
    as_pass = _env("ARCSIGHT_PASSWORD")
    as_verify = _env_bool("ARCSIGHT_VERIFY_SSL", True)
    as_query_uri = _env("ARCSIGHT_QUERY_VIEW_URI")
    edr_vendor = args.edr_vendor or _env("ARCSIGHT_EDR_VENDOR", "Cybereason")
    edr_product = _env("ARCSIGHT_EDR_PRODUCT") or None

    # --- Correlation config ---
    lookback_hours: int = (
        args.lookback
        if args.lookback is not None
        else int(_env("CORRELATION_LOOKBACK_HOURS", "24"))
    )
    edr_limit: int = (
        args.limit
        if args.limit is not None
        else int(_env("CORRELATION_EDR_LIMIT", "25"))
    )
    window_min: int = (
        args.window
        if args.window is not None
        else int(_env("CORRELATION_WINDOW_MIN", "15"))
    )
    output_file: str = (
        args.output
        if args.output
        else _env("CORRELATION_OUTPUT_FILE", "correlation_report.json")
    )

    # --- Validation ---
    missing: list[str] = []
    if not as_url:
        missing.append("ARCSIGHT_URL")
    if not as_user:
        missing.append("ARCSIGHT_USERNAME")
    if not as_pass:
        missing.append("ARCSIGHT_PASSWORD")

    if missing:
        logger.error(
            "Missing required environment variables: %s",
            ", ".join(missing),
        )
        return 1

    logger.info("Configuration:")
    logger.info("  ArcSight URL     : %s (ssl_verify=%s)", as_url, as_verify)
    logger.info("  EDR vendor       : %s", edr_vendor)
    logger.info("  EDR product      : %s", edr_product or "(any)")
    logger.info("  Lookback         : %d hours", lookback_hours)
    logger.info("  EDR event limit  : %d", edr_limit)
    logger.info("  Context window   : ±%d minutes", window_min)
    logger.info("  Output file      : %s", output_file)

    # --- Build client ---
    as_kwargs: dict = dict(
        base_url=as_url,
        username=as_user,
        password=as_pass,
        verify_ssl=as_verify,
        edr_vendor=edr_vendor,
    )
    if as_query_uri:
        as_kwargs["query_view_uri"] = as_query_uri
    if edr_product:
        as_kwargs["edr_product"] = edr_product

    as_client = ArcSightClient(**as_kwargs)

    # --- Connect ---
    logger.info("Authenticating with ArcSight ESM …")
    try:
        as_client.login()
    except Exception as exc:
        logger.error("ArcSight login failed: %s", exc)
        return 2

    if args.dry_run:
        logger.info("Dry-run mode – connectivity OK. Exiting.")
        as_client.logout()
        return 0

    # --- Run correlation ---
    correlator = SecurityEventCorrelator(
        as_client=as_client,
        window_minutes=window_min,
    )

    try:
        report = correlator.run(
            lookback_hours=lookback_hours,
            edr_event_limit=edr_limit,
        )
    except Exception as exc:
        logger.exception("Correlation run failed: %s", exc)
        return 3
    finally:
        try:
            as_client.logout()
        except Exception:
            pass

    # --- Output ---
    _print_summary(report)

    report_dict = _report_to_dict(report)
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report_dict, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    logger.info("JSON report written to %s", output_path.resolve())

    return 0


if __name__ == "__main__":
    sys.exit(main())
