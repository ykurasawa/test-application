"""
Cybereason EDR API Client
Session-based authentication with automatic re-login on session expiry.
"""

import logging
import os
from typing import Any, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class CybereasonClient:
    """Client for the Cybereason EDR REST API."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def login(self) -> None:
        """Authenticate and store the session cookie."""
        url = f"{self.base_url}/rest/login"
        payload = {
            "username": self.username,
            "password": self.password,
        }
        # Cybereason login uses form-encoded data, not JSON
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        resp = self.session.post(
            url,
            data=payload,
            headers=headers,
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        logger.info("Cybereason login successful")

    def _request(
        self,
        method: str,
        path: str,
        retry_on_401: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a request, re-authenticating once on 401."""
        url = f"{self.base_url}{path}"
        resp = self.session.request(
            method, url, verify=self.verify_ssl, timeout=60, **kwargs
        )
        if resp.status_code == 401 and retry_on_401:
            logger.info("Session expired – re-authenticating")
            self.login()
            resp = self.session.request(
                method, url, verify=self.verify_ssl, timeout=60, **kwargs
            )
        resp.raise_for_status()
        return resp

    # ------------------------------------------------------------------
    # Tool: get_alerts
    # ------------------------------------------------------------------

    def get_alerts(
        self,
        status_filter: Optional[list[str]] = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        """
        Retrieve unresolved Malops (alerts) from Cybereason.

        Parameters
        ----------
        status_filter:
            List of malop statuses to filter by.
            Defaults to ["TODO"] (未対応).
        limit:
            Maximum number of malops to return (default 25).
        """
        if status_filter is None:
            status_filter = ["TODO"]

        payload: dict[str, Any] = {
            "totalResultLimit": limit,
            "perGroupLimit": limit,
            "perFeatureLimit": limit,
            "templateContext": "OVERVIEW",
            "queryPath": [
                {
                    "requestedType": "MalopProcess",
                    "filters": [
                        {
                            "facetName": "malopActivityType",
                            "values": ["MALICIOUS_ACTIVITY"],
                        }
                    ],
                    "connectionFeature": {
                        "elementInstanceType": "MalopProcess",
                        "featureName": "suspects",
                    },
                }
            ],
        }

        if status_filter:
            payload["queryPath"][0]["filters"].append(  # type: ignore[index]
                {"facetName": "status", "values": status_filter}
            )

        resp = self._request(
            "POST",
            "/rest/crimes/unified",
            json=payload,
        )
        return resp.json()

    # ------------------------------------------------------------------
    # Tool: get_malop_details
    # ------------------------------------------------------------------

    def get_malop_details(self, malop_id: str) -> dict[str, Any]:
        """
        Retrieve detailed information for a specific Malop.

        Parameters
        ----------
        malop_id:
            The GUID of the Malop (e.g. "11.2345678901234567890").
        """
        payload = {
            "malopGuid": malop_id,
            "requestedType": "MalopProcess",
        }
        resp = self._request(
            "POST",
            "/rest/crimes/get-details",
            json=payload,
        )
        return resp.json()

    # ------------------------------------------------------------------
    # Tool: get_affected_machines
    # ------------------------------------------------------------------

    def get_affected_machines(self, malop_id: str) -> dict[str, Any]:
        """
        List machines affected by a specific Malop.

        Parameters
        ----------
        malop_id:
            The GUID of the Malop.
        """
        payload: dict[str, Any] = {
            "queryPath": [
                {
                    "requestedType": "Machine",
                    "filters": [],
                    "connectionFeature": {
                        "elementInstanceType": "MalopProcess",
                        "featureName": "affectedMachines",
                    },
                    "isResult": True,
                },
                {
                    "requestedType": "MalopProcess",
                    "filters": [
                        {
                            "facetName": "guid",
                            "values": [malop_id],
                        }
                    ],
                },
            ],
            "totalResultLimit": 1000,
            "perGroupLimit": 100,
            "perFeatureLimit": 100,
            "templateContext": "SPECIFIC",
            "queryTimeout": 120000,
        }
        resp = self._request(
            "POST",
            "/rest/crimes/unified",
            json=payload,
        )
        return resp.json()

    # ------------------------------------------------------------------
    # Tool: update_alert_status
    # ------------------------------------------------------------------

    def update_alert_status(
        self,
        malop_id: str,
        status: str,
        comment: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Update the status of a Malop.

        Parameters
        ----------
        malop_id:
            The GUID of the Malop.
        status:
            New status. One of: TODO, CLOSED, FP (false positive),
            OPEN, UNREAD.
        comment:
            Optional comment to add when updating the status.
        """
        valid_statuses = {"TODO", "CLOSED", "FP", "OPEN", "UNREAD"}
        if status not in valid_statuses:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: {', '.join(sorted(valid_statuses))}"
            )

        payload: dict[str, Any] = {
            "malopId": malop_id,
            "newStatus": status,
        }
        if comment:
            payload["comment"] = comment

        resp = self._request(
            "POST",
            "/rest/crimes/update-status",
            json=payload,
        )
        # Some Cybereason versions return 200 with an empty body on success
        try:
            return resp.json()
        except ValueError:
            return {"status": "ok", "malopId": malop_id, "newStatus": status}
