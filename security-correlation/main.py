"""
Security Event Correlation Application
ArcSight ESM × Cybereason EDR

Usage
-----
  # Run with environment variables:
  python main.py

  # Override defaults via CLI flags:
  python main.py --status TODO Pending --limit 50 --output report.json

Environment Variables
---------------------
  ARCSIGHT_URL             ArcSight ESM base URL
  ARCSIGHT_USERNAME        ArcSight username
  ARCSIGHT_PASSWORD        ArcSight password
  ARCSIGHT_VERIFY_SSL      "false" to skip TLS check (default: true)
  ARCSIGHT_QUERY_VIEW_URI  ArcSight Query View resource URI (optional)

  CYBEREASON_URL           Cybereason tenant URL
  CYBEREASON_USERNAME      Cybereason username
  CYBEREASON_PASSWORD      Cybereason password
  CYBEREASON_VERIFY_SSL    "false" to skip TLS check (default: true)

  CORRELATION_STATUS_FILTER  Comma-separated MalOp statuses (default: TODO)
  CORRELATION_MALOP_LIMIT    Max MalOps to process (default: 25)
  CORRELATION_WINDOW_MIN     Time window in minutes (default: 15)
  CORRELATION_OUTPUT_FILE    Output JSON path (default: correlation_report.json)
  CORRELATION_ENRICH_IPS     "false" to skip machine IP enrichment (default: true)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from arcsight_client import ArcSightClient
from cybereason_client import CybereasonClient
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
            "malop_guid": r.malop_guid,
            "malop_name": r.malop_name,
            "malop_severity": r.malop_severity,
            "malop_status": r.malop_status,
            "malop_timestamp_iso": r.malop_timestamp_iso,
            "indicators": {
                "hostnames": r.hostnames,
                "source_ips": r.source_ips,
                "dest_ips": r.dest_ips,
            },
            "time_window": {
                "start_iso": r.window_start_iso,
                "end_iso": r.window_end_iso,
                "window_minutes": report.window_minutes,
            },
            "arcsight_event_count": r.arcsight_event_count,
            "arcsight_events": r.arcsight_events,
            "error": r.error,
        }

    return {
        "generated_at": report.generated_at,
        "window_minutes": report.window_minutes,
        "summary": {
            "total_malops": report.total_malops,
            "total_arcsight_events": report.total_arcsight_events,
            "malops_with_matches": sum(
                1 for r in report.results if r.arcsight_event_count > 0
            ),
            "malops_with_errors": sum(
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
    print(f"  Generated : {report.generated_at}")
    print(f"  Window    : ±{report.window_minutes} minutes")
    print(sep)
    print(
        f"  MalOps processed   : {report.total_malops}"
    )
    print(
        f"  ArcSight events    : {report.total_arcsight_events}"
    )
    matched = sum(1 for r in report.results if r.arcsight_event_count > 0)
    print(f"  MalOps with hits   : {matched}")
    print(sep)

    for idx, result in enumerate(report.results, start=1):
        print(
            f"\n[{idx}/{report.total_malops}] "
            f"MalOp: {result.malop_name or result.malop_guid}"
        )
        print(f"  GUID      : {result.malop_guid}")
        print(f"  Severity  : {result.malop_severity}")
        print(f"  Status    : {result.malop_status}")
        print(f"  Timestamp : {result.malop_timestamp_iso}")
        print(
            f"  Window    : {result.window_start_iso} – {result.window_end_iso}"
        )
        print(f"  Hostnames : {', '.join(result.hostnames) or '(none)'}")
        print(f"  Source IPs: {', '.join(result.source_ips) or '(none)'}")
        print(f"  Dest IPs  : {', '.join(result.dest_ips) or '(none)'}")

        if result.error:
            print(f"  ERROR     : {result.error}")
        else:
            print(f"  ArcSight  : {result.arcsight_event_count} events correlated")

            for evt in result.arcsight_events[:5]:
                evt_time = evt.get("endTime") or evt.get("startTime") or ""
                evt_name = evt.get("name") or evt.get("message") or "(unnamed)"
                evt_src = evt.get("sourceAddress", "")
                evt_dst = evt.get("destinationAddress", "")
                evt_sev = evt.get("severity", "")
                print(
                    f"    • [{evt_time}] {evt_name}"
                    f"  src={evt_src} dst={evt_dst} sev={evt_sev}"
                )
            if result.arcsight_event_count > 5:
                print(
                    f"    … and {result.arcsight_event_count - 5} more "
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
            "Correlate Cybereason EDR MalOps with ArcSight ESM events "
            "in a ±15-minute window."
        ),
    )
    parser.add_argument(
        "--status",
        nargs="+",
        metavar="STATUS",
        default=None,
        help=(
            "Cybereason investigationStatus values to process. "
            "Default: value of CORRELATION_STATUS_FILTER env var, or 'TODO'."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Max number of MalOps to process (default 25).",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=None,
        metavar="MINUTES",
        help="Time window in minutes around each event (default 15).",
    )
    parser.add_argument(
        "--output",
        default=None,
        metavar="FILE",
        help="Path to write the JSON report (default: correlation_report.json).",
    )
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip Cybereason machine IP enrichment API call.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Validate configuration and connectivity only; "
            "do not run correlation."
        ),
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

    # --- Cybereason config ---
    cr_url = _env("CYBEREASON_URL")
    cr_user = _env("CYBEREASON_USERNAME")
    cr_pass = _env("CYBEREASON_PASSWORD")
    cr_verify = _env_bool("CYBEREASON_VERIFY_SSL", True)

    # --- Correlation config ---
    raw_status = _env("CORRELATION_STATUS_FILTER", "TODO")
    status_filter: list[str] = (
        args.status
        if args.status
        else [s.strip() for s in raw_status.split(",") if s.strip()]
    )
    malop_limit: int = (
        args.limit
        if args.limit is not None
        else int(_env("CORRELATION_MALOP_LIMIT", "25"))
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
    enrich_ips: bool = (
        not args.no_enrich
        and _env_bool("CORRELATION_ENRICH_IPS", True)
    )

    # --- Validation ---
    missing: list[str] = []
    if not as_url:
        missing.append("ARCSIGHT_URL")
    if not as_user:
        missing.append("ARCSIGHT_USERNAME")
    if not as_pass:
        missing.append("ARCSIGHT_PASSWORD")
    if not cr_url:
        missing.append("CYBEREASON_URL")
    if not cr_user:
        missing.append("CYBEREASON_USERNAME")
    if not cr_pass:
        missing.append("CYBEREASON_PASSWORD")

    if missing:
        logger.error(
            "Missing required environment variables: %s",
            ", ".join(missing),
        )
        return 1

    logger.info("Configuration:")
    logger.info("  ArcSight URL     : %s (ssl_verify=%s)", as_url, as_verify)
    logger.info("  Cybereason URL   : %s (ssl_verify=%s)", cr_url, cr_verify)
    logger.info("  Status filter    : %s", status_filter)
    logger.info("  MalOp limit      : %d", malop_limit)
    logger.info("  Time window      : ±%d minutes", window_min)
    logger.info("  Output file      : %s", output_file)
    logger.info("  IP enrichment    : %s", enrich_ips)

    # --- Build clients ---
    as_kwargs: dict = dict(
        base_url=as_url,
        username=as_user,
        password=as_pass,
        verify_ssl=as_verify,
    )
    if as_query_uri:
        as_kwargs["query_view_uri"] = as_query_uri

    as_client = ArcSightClient(**as_kwargs)
    cr_client = CybereasonClient(
        base_url=cr_url,
        username=cr_user,
        password=cr_pass,
        verify_ssl=cr_verify,
    )

    # --- Connect ---
    logger.info("Authenticating with Cybereason EDR …")
    try:
        cr_client.login()
    except Exception as exc:
        logger.error("Cybereason login failed: %s", exc)
        return 2

    logger.info("Authenticating with ArcSight ESM …")
    try:
        as_client.login()
    except Exception as exc:
        logger.error("ArcSight login failed: %s", exc)
        return 3

    if args.dry_run:
        logger.info("Dry-run mode – connectivity OK. Exiting.")
        return 0

    # --- Run correlation ---
    correlator = SecurityEventCorrelator(
        cr_client=cr_client,
        as_client=as_client,
        window_minutes=window_min,
        enrich_machine_ips=enrich_ips,
    )

    try:
        report = correlator.run(
            status_filter=status_filter,
            malop_limit=malop_limit,
        )
    except Exception as exc:
        logger.exception("Correlation run failed: %s", exc)
        return 4
    finally:
        try:
            as_client.logout()
        except Exception:
            pass

    # --- Output ---
    _print_summary(report)

    report_dict = _report_to_dict(report)
    output_path = Path(output_file)
    output_path.write_text(
        json.dumps(report_dict, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    logger.info("JSON report written to %s", output_path.resolve())

    return 0


if __name__ == "__main__":
    sys.exit(main())
