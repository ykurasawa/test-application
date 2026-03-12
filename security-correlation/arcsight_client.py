"""
ArcSight ESM REST API Client

Session-based authentication and security event retrieval.

Reference: ArcSight ESM REST Developer's Guide
  - Login:  POST /www/core-service/rest/LoginService/login
  - Logout: POST /www/core-service/rest/LoginService/logout
  - Events: POST /www/manager-service/rest/QueryViewService/getSecurityEvents

Environment variables:
  ARCSIGHT_URL             Base URL (e.g. https://arcsight.example.com:8443)
  ARCSIGHT_USERNAME        Login username
  ARCSIGHT_PASSWORD        Login password
  ARCSIGHT_VERIFY_SSL      "false" to skip TLS verification (default: true)
  ARCSIGHT_QUERY_VIEW_URI  URI of the Query View resource (optional)
  ARCSIGHT_EDR_VENDOR      deviceVendor value for EDR events (default: Cybereason)
  ARCSIGHT_EDR_PRODUCT     deviceProduct value for EDR events (optional)
"""

import datetime
import json
import logging
from typing import Any, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Default Query View URI used when none is provided
_DEFAULT_QUERY_URI = (
    "/All Query Views/ArcSight System Query Views/Default All Events"
)


class ArcSightClient:
    """Client for the ArcSight ESM REST API."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        query_view_uri: str = _DEFAULT_QUERY_URI,
        edr_vendor: str = "Cybereason",
        edr_product: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.query_view_uri = query_view_uri
        self.edr_vendor = edr_vendor
        self.edr_product = edr_product
        self.session = requests.Session()
        self._auth_token: Optional[str] = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def login(self) -> None:
        """
        Authenticate against ArcSight ESM and store the auth token.

        POST /www/core-service/rest/LoginService/login
        Request body:
          {"log.login": {"log.login": "<user>", "log.password": "<pass>"}}
        Response:
          {"log.loginResponse": {"log.return": "<TOKEN>"}}
        """
        self.session = requests.Session()
        login_url = f"{self.base_url}/www/core-service/rest/LoginService/login"
        payload = {
            "log.login": {
                "log.login": self.username,
                "log.password": self.password,
            }
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        resp = self.session.post(
            login_url,
            data=json.dumps(payload),
            headers=headers,
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()

        token = (
            data.get("log.loginResponse", {}).get("log.return")
            or data.get("loginResponse", {}).get("return")
        )
        if not token:
            raise RuntimeError(
                "ArcSight login succeeded but no auth token received. "
                f"Response: {data}"
            )

        self._auth_token = token
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        logger.info("ArcSight ESM login successful (token length=%d)", len(token))

    def logout(self) -> None:
        """
        Invalidate the current session.
        POST /www/core-service/rest/LoginService/logout?authToken=<TOKEN>
        """
        if not self._auth_token:
            return
        logout_url = f"{self.base_url}/www/core-service/rest/LoginService/logout"
        try:
            self.session.post(
                logout_url,
                params={"authToken": self._auth_token},
                verify=self.verify_ssl,
                timeout=10,
            )
            logger.info("ArcSight ESM logout successful")
        except Exception as exc:
            logger.warning("ArcSight logout error (ignored): %s", exc)
        finally:
            self._auth_token = None

    def _request(
        self,
        method: str,
        path: str,
        retry_on_401: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a request, re-authenticating once on HTTP 401."""
        url = f"{self.base_url}{path}"
        resp = self.session.request(
            method, url, verify=self.verify_ssl, timeout=60, **kwargs
        )
        if resp.status_code == 401 and retry_on_401:
            logger.info("ArcSight session expired – re-authenticating")
            self.login()
            resp = self.session.request(
                method, url, verify=self.verify_ssl, timeout=60, **kwargs
            )
        resp.raise_for_status()
        return resp

    # ------------------------------------------------------------------
    # Internal query helper
    # ------------------------------------------------------------------

    def _query_events(
        self,
        start_time_ms: int,
        end_time_ms: int,
        filter_expression: Optional[str],
        max_results: int,
    ) -> list[dict[str, Any]]:
        """
        Execute a security event query against ArcSight ESM.

        POST /www/manager-service/rest/QueryViewService/getSecurityEvents

        Parameters
        ----------
        start_time_ms : int
            Window start in epoch milliseconds.
        end_time_ms : int
            Window end in epoch milliseconds.
        filter_expression : str or None
            ArcSight filter expression string (SQL-like).
            Example: "sourceAddress = '1.2.3.4' OR deviceHostName CONTAINS 'srv01'"
        max_results : int
            Maximum number of events returned.

        Returns
        -------
        list[dict]
            List of raw ArcSight event objects.
            Common fields: eventId, endTime, name, type, severity,
            sourceAddress, destinationAddress, deviceHostName,
            deviceProduct, deviceVendor, message.
        """
        payload: dict[str, Any] = {
            "qvs.getSecurityEventsRequest": {
                "qvs.id": {
                    "qvs.uri": self.query_view_uri,
                    "qvs.isInArcSightSystem": True,
                },
                "qvs.queryParam": {
                    "qvs.startTime": start_time_ms,
                    "qvs.endTime": end_time_ms,
                    "qvs.maxResults": max_results,
                },
            }
        }

        if filter_expression:
            payload["qvs.getSecurityEventsRequest"]["qvs.queryParam"][
                "qvs.filterExpression"
            ] = filter_expression

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        resp = self._request(
            "POST",
            "/www/manager-service/rest/QueryViewService/getSecurityEvents",
            data=json.dumps(payload),
            headers=headers,
        )
        data = resp.json()

        # Normalise the response envelope (varies across ESM versions)
        raw = (
            data.get("qvs.getSecurityEventsResponse", {}).get("qvs.return")
            or data.get("getSecurityEventsResponse", {}).get("return")
            or []
        )
        if isinstance(raw, dict):
            raw = [raw]
        return raw or []

    # ------------------------------------------------------------------
    # EDR event retrieval (Step 1: seed events)
    # ------------------------------------------------------------------

    def get_edr_events(
        self,
        start_time_ms: int,
        end_time_ms: int,
        max_results: int = 200,
    ) -> list[dict[str, Any]]:
        """
        Fetch Cybereason EDR events stored in ArcSight ESM.

        Filters by ``deviceVendor = '<edr_vendor>'`` and optionally
        ``deviceProduct = '<edr_product>'``.  Both values are set on the
        client via constructor parameters (``edr_vendor`` / ``edr_product``).

        Parameters
        ----------
        start_time_ms : int
            Lookback window start in epoch milliseconds.
        end_time_ms : int
            Lookback window end in epoch milliseconds (typically now).
        max_results : int
            Maximum number of EDR events to retrieve.

        Returns
        -------
        list[dict]
            List of ArcSight event objects originating from the EDR sensor.
            Key fields used downstream:
              sourceAddress      – source IP of the EDR alert
              destinationAddress – destination IP of the EDR alert
              deviceHostName     – hostname where the EDR agent is installed
              endTime            – event timestamp (epoch ms)
              name / message     – alert description
              severity           – alert severity
        """
        conditions = [f"deviceVendor = '{self.edr_vendor}'"]
        if self.edr_product:
            conditions.append(f"deviceProduct = '{self.edr_product}'")
        filter_expr = " AND ".join(conditions)

        logger.info(
            "Fetching EDR events from ArcSight (vendor=%s, product=%s, "
            "window %s – %s, max=%d)",
            self.edr_vendor,
            self.edr_product or "*",
            _ms_to_iso(start_time_ms),
            _ms_to_iso(end_time_ms),
            max_results,
        )

        events = self._query_events(
            start_time_ms=start_time_ms,
            end_time_ms=end_time_ms,
            filter_expression=filter_expr,
            max_results=max_results,
        )
        logger.info("Fetched %d EDR events from ArcSight", len(events))
        return events

    # ------------------------------------------------------------------
    # Correlated event retrieval (Step 2: context events)
    # ------------------------------------------------------------------

    def search_events(
        self,
        start_time_ms: int,
        end_time_ms: int,
        source_address: Optional[str] = None,
        destination_address: Optional[str] = None,
        device_hostname: Optional[str] = None,
        max_results: int = 200,
    ) -> list[dict[str, Any]]:
        """
        Query all security events in a time window, filtered by at least one
        of: source IP, destination IP, or device hostname.

        Used in the correlation phase to retrieve context events surrounding
        each EDR alert.

        Parameters
        ----------
        start_time_ms : int
            Window start in epoch milliseconds.
        end_time_ms : int
            Window end in epoch milliseconds.
        source_address : str, optional
            Filter: source IP address (exact match).
        destination_address : str, optional
            Filter: destination IP address (exact match).
        device_hostname : str, optional
            Filter: device host name (substring match).
        max_results : int
            Maximum number of events returned (default 200).

        Returns
        -------
        list[dict]
        """
        conditions: list[str] = []
        if source_address:
            conditions.append(f"sourceAddress = '{source_address}'")
        if destination_address:
            conditions.append(f"destinationAddress = '{destination_address}'")
        if device_hostname:
            conditions.append(f"deviceHostName CONTAINS '{device_hostname}'")

        filter_expr = " OR ".join(conditions) if conditions else None

        events = self._query_events(
            start_time_ms=start_time_ms,
            end_time_ms=end_time_ms,
            filter_expression=filter_expr,
            max_results=max_results,
        )
        logger.info(
            "ArcSight context search returned %d events "
            "(window %s – %s, src=%s, dst=%s, host=%s)",
            len(events),
            _ms_to_iso(start_time_ms),
            _ms_to_iso(end_time_ms),
            source_address,
            destination_address,
            device_hostname,
        )
        return events


# ------------------------------------------------------------------
# Utility
# ------------------------------------------------------------------


def _ms_to_iso(ms: int) -> str:
    """Convert epoch milliseconds to ISO-8601 string (UTC)."""
    dt = datetime.datetime.fromtimestamp(ms / 1000.0, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
