"""
ArcSight ESM REST API Client

Session-based authentication and security event retrieval.

Reference: ArcSight ESM REST Developer's Guide
  - Login:  POST /www/core-service/rest/LoginService/login
  - Logout: POST /www/core-service/rest/LoginService/logout
  - Events: POST /www/manager-service/rest/QueryViewService/getSecurityEvents

Environment variables:
  ARCSIGHT_URL           Base URL (e.g. https://arcsight.example.com:8443)
  ARCSIGHT_USERNAME      Login username
  ARCSIGHT_PASSWORD      Login password
  ARCSIGHT_VERIFY_SSL    "false" to skip TLS verification (default: true)
  ARCSIGHT_QUERY_VIEW_URI  URI of the Query View resource (optional)
"""

import json
import logging
import time
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
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.query_view_uri = query_view_uri
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
    # Security event retrieval
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
        Query security events from ArcSight ESM in a time window.

        POST /www/manager-service/rest/QueryViewService/getSecurityEvents

        The query is executed against ``self.query_view_uri``.  At least one
        filter (source IP, destination IP, or hostname) should be supplied to
        keep the result set manageable.

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
            List of raw ArcSight event objects.
            Common fields: eventId, endTime, name, type, severity,
            sourceAddress, destinationAddress, deviceHostName,
            deviceProduct, deviceVendor, message.
        """
        # Build a simple filter expression understood by ArcSight ESM
        conditions: list[str] = []
        if source_address:
            conditions.append(f"sourceAddress = '{source_address}'")
        if destination_address:
            conditions.append(f"destinationAddress = '{destination_address}'")
        if device_hostname:
            conditions.append(f"deviceHostName CONTAINS '{device_hostname}'")

        filter_expr = " OR ".join(conditions) if conditions else None

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

        if filter_expr:
            payload["qvs.getSecurityEventsRequest"]["qvs.queryParam"][
                "qvs.filterExpression"
            ] = filter_expr

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
        events: list[dict[str, Any]] = raw or []

        logger.info(
            "ArcSight search returned %d events "
            "(window %s – %s, src=%s, dst=%s, host=%s)",
            len(events),
            _ms_to_iso(start_time_ms),
            _ms_to_iso(end_time_ms),
            source_address,
            destination_address,
            device_hostname,
        )
        return events

    def get_event_by_id(self, event_id: str) -> Optional[dict[str, Any]]:
        """
        Retrieve a single event by its ArcSight event ID.
        GET /www/manager-service/rest/SecurityEventService/getSecurityEventDetails
        """
        params = {"eventId": event_id}
        resp = self._request(
            "GET",
            "/www/manager-service/rest/SecurityEventService/getSecurityEventDetails",
            params=params,
        )
        data = resp.json()
        return data.get("ses.getSecurityEventDetailsResponse", {}).get(
            "ses.return"
        )


# ------------------------------------------------------------------
# Utility
# ------------------------------------------------------------------


def _ms_to_iso(ms: int) -> str:
    """Convert epoch milliseconds to ISO-8601 string (UTC)."""
    import datetime

    dt = datetime.datetime.fromtimestamp(ms / 1000.0, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
