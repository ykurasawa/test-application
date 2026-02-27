"""
Cybereason EDR API Client
Session-based authentication with automatic re-login on session expiry.
Reference: Cybereason Knowledge Base (nest.cybereason.com)
           - Retrieve All MalOps: POST /rest/mmng/v2/malops
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
        Authenticate and store the session cookie.
        Based on official Cybereason API documentation Python sample:
          session.post(login_url, data={"username":..., "password":...})
        """
        self.session = requests.Session()
        login_url = f"{self.base_url}/login.html"
        data = {
            "username": self.username,
            "password": self.password,
        }
        resp = self.session.post(
            login_url,
            data=data,
            verify=self.verify_ssl,
            timeout=30,
        )
        resp.raise_for_status()
        if not self.session.cookies.get("JSESSIONID"):
            raise RuntimeError("Login succeeded but no JSESSIONID cookie received.")
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
    # Internal helper: /rest/mmng/v2/malops
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
        POST /rest/mmng/v2/malops の共通ラッパー。

        Reference: "Retrieve All MalOps" - Cybereason Knowledge Base
          Endpoint URL : https://<server>/rest/mmng/v2/malops
          Action       : POST
          Supported    : version 23.1.152 and higher (new Data Platform)
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
            "federation": {
                "groups": [],
            },
            "filter": {
                "malop": malop_filter or {},
            },
            "sort": [
                {
                    "field": sort_field,
                    "order": sort_order,
                }
            ],
        }

        headers = {"Content-Type": "application/json"}
        resp = self._request(
            "POST",
            "/rest/mmng/v2/malops",
            data=json.dumps(payload),
            headers=headers,
        )
        return resp.json()

    # ------------------------------------------------------------------
    # Tool: get_alerts
    # ------------------------------------------------------------------

    def get_alerts(
        self,
        status_filter: Optional[list[str]] = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        """
        Retrieve MalOps via POST /rest/mmng/v2/malops.

        Parameters
        ----------
        status_filter : list[str]
            Filter by investigationStatus. Possible values:
            "TODO", "Pending", "UnderInvestigation", "OnHold", "Closed", "Reopened"
            Defaults to ["TODO"].
        limit : int
            Number of MalOps to return per page (pageSize).

        Returns
        -------
        dict
            Raw API response. Key fields:
              data.data       - list of MalOp objects
              data.totalHits  - total number of matching MalOps
              data.pageSize   - page size used
              data.pages      - number of pages
        """
        if status_filter is None:
            status_filter = ["TODO"]

        return self._query_malops(
            malop_filter={"investigationStatus": status_filter},
            page_size=limit,
        )

    # ------------------------------------------------------------------
    # Tool: get_malop_details
    # ------------------------------------------------------------------

    def get_malop_details(self, malop_id: str) -> dict[str, Any]:
        """
        Retrieve detailed information for a specific Malop.
        Uses POST /rest/mmng/v2/malops with search.malop.guid filter.

        Returns
        -------
        dict
            Single MalOp object. Key fields (PDFマニュアル Response Success Schema より):
              guid                  - MalOp の一意識別子
              displayName           - MalOp の表示名 (通常はルート原因の名前)
              creationTime          - 生成時刻 (ms)
              lastUpdateTime        - 最終更新時刻 (ms)
              status                - Active / Remediated / Closed / Excluded
              investigationStatus   - Pending / UnderInvestigation / OnHold / Closed 等
              severity              - High / Medium / Low
              priority              - HIGH / MEDIUM / LOW / null
              detectionEngines      - 検出エンジン (EDR / AntiVirus 等)
              detectionTypes        - 検出種別
              detectionType         - MalOp 種別 (CUSTOM_RULE / RANSOMWARE 等)
              mitreTactics          - MITRE ATT&CK タクティクス
              iocs                  - IOC 種別 (File / Process / IpAddress 等)
              escalated             - エスカレーション済みフラグ
              isEdr                 - AI Hunt MalOp フラグ
              rootCauseElementType  - ルート原因の Element 種別
              machines              - 関連マシン一覧
              users                 - 関連ユーザー一覧
        """
        data = self._query_malops(
            search={"malop": {"guid": malop_id}},
            page_size=1,
        )

        malops: list[dict] = data.get("data", {}).get("data", [])
        if not malops:
            raise ValueError(f"MalOp not found: {malop_id}")

        return malops[0]

    # ------------------------------------------------------------------
    # Tool: get_affected_machines
    # ------------------------------------------------------------------

    def get_affected_machines(self, malop_id: str) -> dict[str, Any]:
        """
        List machines and users affected by a specific Malop.
        Reuses get_malop_details (POST /rest/mmng/v2/malops) and extracts
        the machines / users fields.

        Returns
        -------
        dict with keys:
          malopGuid - 検索に使用した MalOp GUID
          machines  - 関連マシン一覧 (guid / displayName / connected /
                      isolated / osType / lastConnected)
          users     - 関連ユーザー一覧 (guid / displayName / admin /
                      domainUser / localSystem)
        """
        malop = self.get_malop_details(malop_id)
        return {
            "malopGuid": malop_id,
            "machines": malop.get("machines", []),
            "users": malop.get("users", []),
        }

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
        Update the investigation status of a Malop.
        Uses PUT /rest/mmng/v2/malops/{malopGUID}

        Reference: "Update the Malop Investigation Status" - Cybereason Knowledge Base
          Endpoint URL : https://<server>/rest/mmng/v2/malops/:malopGUID
          Action       : PUT
          Supported    : version 21.2.180 and higher (new Data Platform)

        Parameters
        ----------
        malop_id : str
            The GUID of the target MalOp.
        status : str
            New investigationStatus. Possible values:
            "Pending"            - 未対応
            "UnderInvestigation" - 調査中
            "OnHold"             - 保留
            "Closed"             - クローズ
            "ReOpened"           - 再オープン
        comment : str, optional
            Comment to attach to the status change. (ログ用、APIには送信しない)
        """
        valid_statuses = {"Pending", "UnderInvestigation", "OnHold", "Closed", "ReOpened"}
        if status not in valid_statuses:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: {', '.join(sorted(valid_statuses))}"
            )

        payload: dict[str, Any] = {"investigationStatus": status}

        headers = {"Content-Type": "application/json"}
        resp = self._request(
            "PUT",
            f"/rest/mmng/v2/malops/{malop_id}",
            data=json.dumps(payload),
            headers=headers,
        )
        if comment:
            logger.info("Status update comment: %s", comment)
        try:
            return resp.json()
        except ValueError:
            return {"status": "ok", "malopId": malop_id, "newStatus": status}