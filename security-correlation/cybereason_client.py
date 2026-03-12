"""
Cybereason EDR REST API Client

Session-based authentication, MalOp retrieval, and machine/IP extraction.

Reference: Cybereason Knowledge Base (nest.cybereason.com)
  - Login:          POST /login.html
  - MalOps list:    POST /rest/mmng/v2/malops
  - Machine query:  POST /rest/visualsearch/query/simple

Environment variables:
  CYBEREASON_URL         Base URL (e.g. https://tenant.cybereason.net)
  CYBEREASON_USERNAME    Login username
  CYBEREASON_PASSWORD    Login password
  CYBEREASON_VERIFY_SSL  "false" to skip TLS verification (default: true)
"""

import json
import logging
import time
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

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def login(self) -> None:
        """
        Authenticate and store the session cookie (JSESSIONID).
        POST /login.html
        """
        self.session = requests.Session()
        login_url = f"{self.base_url}/login.html"
        resp = self.session.post(
            login_url,
            data={"username": self.username, "password": self.password},
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        if not self.session.cookies.get("JSESSIONID"):
            raise RuntimeError(
                "Cybereason login succeeded but no JSESSIONID cookie received."
            )
        logger.info(
            "Cybereason login successful, JSESSIONID: %s",
            self.session.cookies.get("JSESSIONID"),
        )

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
            logger.info("Cybereason session expired – re-authenticating")
            self.login()
            resp = self.session.request(
                method, url, verify=self.verify_ssl, timeout=60, **kwargs
            )
        resp.raise_for_status()
        return resp

    # ------------------------------------------------------------------
    # MalOp retrieval
    # ------------------------------------------------------------------

    def _query_malops(
        self,
        search: Optional[dict] = None,
        page_size: int = 25,
        offset: int = 0,
        malop_filter: Optional[dict] = None,
        sort_field: str = "lastUpdateTime",
        sort_order: str = "desc",
    ) -> dict[str, Any]:
        """
        POST /rest/mmng/v2/malops  (Cybereason Data Platform v23.1.152+)
        """
        payload: dict[str, Any] = {
            "search": search or {},
            "range": {
                "from": 0,
                "to": int(time.time() * 1000),
            },
            "pagination": {
                "pageSize": page_size,
                "offset": offset,
            },
            "federation": {"groups": []},
            "filter": {"malop": malop_filter or {}},
            "sort": [{"field": sort_field, "order": sort_order}],
        }
        headers = {"Content-Type": "application/json"}
        resp = self._request(
            "POST",
            "/rest/mmng/v2/malops",
            data=json.dumps(payload),
            headers=headers,
        )
        return resp.json()

    def get_malops(
        self,
        status_filter: Optional[list[str]] = None,
        limit: int = 25,
    ) -> list[dict[str, Any]]:
        """
        Return a list of MalOp objects, filtered by investigationStatus.

        Parameters
        ----------
        status_filter : list[str]
            Investigation statuses to include.
            Values: "TODO", "Pending", "UnderInvestigation", "OnHold",
                    "Closed", "Reopened"
            Defaults to ["TODO"].
        limit : int
            Maximum number of MalOps to return.

        Returns
        -------
        list[dict]
            Each item contains (among others):
              guid              – MalOp unique identifier
              displayName       – human-readable name
              creationTime      – epoch ms
              lastUpdateTime    – epoch ms
              severity          – High / Medium / Low
              status            – Active / Remediated / Closed
              investigationStatus
              machines          – list of affected machine objects
              users             – list of affected user objects
              iocs              – list of IOC objects
              mitreTactics
        """
        if status_filter is None:
            status_filter = ["TODO"]
        data = self._query_malops(
            malop_filter={"investigationStatus": status_filter},
            page_size=limit,
        )
        return data.get("data", {}).get("data", [])

    def get_malop_details(self, malop_id: str) -> dict[str, Any]:
        """Return full details for a single MalOp GUID."""
        data = self._query_malops(
            search={"malop": {"guid": malop_id}},
            page_size=1,
        )
        malops: list[dict] = data.get("data", {}).get("data", [])
        if not malops:
            raise ValueError(f"MalOp not found: {malop_id}")
        return malops[0]

    # ------------------------------------------------------------------
    # Machine / IP enrichment
    # ------------------------------------------------------------------

    def get_machine_details(
        self, machine_guids: list[str]
    ) -> list[dict[str, Any]]:
        """
        Retrieve machine details (including internal IP addresses) for the
        given machine GUIDs using the Cybereason Query API.

        POST /rest/visualsearch/query/simple

        The response element path to IP addresses:
          data.resultIdToElementDataMap.<machine_guid>
            .simpleValues.internalIpAddress.values[]
            .simpleValues.externalIpAddress.values[]

        Returns
        -------
        list[dict]
            List of enriched machine records with added keys:
              internalIps  – list of internal IP addresses
              externalIps  – list of external IP addresses
        """
        if not machine_guids:
            return []

        payload: dict[str, Any] = {
            "queryPath": [
                {
                    "requestedType": "Machine",
                    "filters": [
                        {
                            "facetName": "guid",
                            "values": machine_guids,
                            "filterType": "Equals",
                        }
                    ],
                    "isResult": True,
                }
            ],
            "totalResultLimit": len(machine_guids) * 2,
            "perGroupLimit": 100,
            "perFeatureLimit": 100,
            "templateContext": "OVERVIEW",
            "queryTimeout": 120000,
        }
        headers = {"Content-Type": "application/json"}
        try:
            resp = self._request(
                "POST",
                "/rest/visualsearch/query/simple",
                data=json.dumps(payload),
                headers=headers,
            )
            data = resp.json()
        except Exception as exc:
            logger.warning("Machine detail query failed: %s", exc)
            return []

        result_map: dict = (
            data.get("data", {})
            .get("resultIdToElementDataMap", {})
        )
        machines: list[dict[str, Any]] = []
        for guid, element in result_map.items():
            simple = element.get("simpleValues", {})
            machine: dict[str, Any] = {"guid": guid}

            # Hostname
            hn_values = simple.get("displayName", {}).get("values", [])
            machine["displayName"] = hn_values[0] if hn_values else guid

            # Internal IPs
            int_values = simple.get("internalIpAddress", {}).get("values", [])
            machine["internalIps"] = int_values

            # External IPs
            ext_values = simple.get("externalIpAddress", {}).get("values", [])
            machine["externalIps"] = ext_values

            machines.append(machine)

        return machines

    # ------------------------------------------------------------------
    # Indicator extraction
    # ------------------------------------------------------------------

    def extract_indicators(
        self, malop: dict[str, Any], enrich_ips: bool = True
    ) -> dict[str, Any]:
        """
        Extract correlation indicators from a MalOp object.

        Indicators collected:
          - hostnames    : machine displayNames from malop["machines"]
          - source_ips   : internal/external IPs from machine details
          - dest_ips     : destination IPs from malop IOCs of type IpAddress
          - timestamp_ms : malop["lastUpdateTime"] or malop["creationTime"]

        Parameters
        ----------
        malop : dict
            A MalOp object as returned by get_malops() / get_malop_details().
        enrich_ips : bool
            When True, calls get_machine_details() to fetch actual IP
            addresses for each affected machine.

        Returns
        -------
        dict with keys:
          malop_guid    str
          timestamp_ms  int   (epoch milliseconds)
          hostnames     list[str]
          source_ips    list[str]
          dest_ips      list[str]
        """
        malop_guid = malop.get("guid", "")
        timestamp_ms: int = int(
            malop.get("lastUpdateTime") or malop.get("creationTime") or 0
        )

        hostnames: list[str] = []
        source_ips: list[str] = []
        dest_ips: list[str] = []
        machine_guids: list[str] = []

        # --- Machines (hostnames + guids for IP enrichment) ---
        for machine in malop.get("machines", []):
            name = (
                machine.get("displayName")
                or machine.get("name")
                or machine.get("guid", "")
            )
            if name and name not in hostnames:
                hostnames.append(name)

            mguid = machine.get("guid")
            if mguid:
                machine_guids.append(mguid)

            # IPs may already be present in the MalOp summary
            for ip_key in ("ipAddress", "ip", "internalIpAddress"):
                ip = machine.get(ip_key)
                if ip and ip not in source_ips:
                    source_ips.append(ip)

        # --- IP enrichment via machine detail API ---
        if enrich_ips and machine_guids:
            machine_details = self.get_machine_details(machine_guids)
            for md in machine_details:
                for ip in md.get("internalIps", []):
                    if ip and ip not in source_ips:
                        source_ips.append(ip)
                for ip in md.get("externalIps", []):
                    if ip and ip not in source_ips:
                        source_ips.append(ip)

        # --- IOCs (IpAddress type → destination IPs) ---
        for ioc in malop.get("iocs", []):
            ioc_type = ioc.get("type", "")
            value = ioc.get("value", "")
            if not value:
                continue
            if ioc_type == "IpAddress":
                if value not in dest_ips:
                    dest_ips.append(value)

        logger.info(
            "MalOp %s: hostnames=%s source_ips=%s dest_ips=%s ts=%s",
            malop_guid,
            hostnames,
            source_ips,
            dest_ips,
            timestamp_ms,
        )
        return {
            "malop_guid": malop_guid,
            "timestamp_ms": timestamp_ms,
            "hostnames": hostnames,
            "source_ips": source_ips,
            "dest_ips": dest_ips,
        }
