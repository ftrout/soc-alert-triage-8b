"""SOAR Platform Integration Adapters.
=====================================

Provides adapters for integrating Kodiak SecOps 1 with popular
Security Orchestration, Automation and Response (SOAR) platforms.

Supported platforms:
- Splunk SOAR (Phantom)
- Palo Alto XSOAR (Demisto)
- IBM Resilient
- Generic Webhook

Example:
    >>> from soc_triage_agent.soar_adapters import XSOARAdapter
    >>> adapter = XSOARAdapter(base_url="https://xsoar.company.com")
    >>> adapter.send_triage_result(alert_id, prediction)

"""

import hashlib
import hmac
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class SOARIncident:
    """Standardized incident format for SOAR platforms."""

    incident_id: str
    name: str
    severity: str  # low, medium, high, critical
    status: str  # new, in_progress, closed
    description: str
    labels: list[str]
    raw_data: dict[str, Any]

    # Triage results
    triage_decision: Optional[str] = None
    triage_priority: Optional[int] = None
    triage_reasoning: Optional[str] = None
    triage_actions: Optional[list[str]] = None
    triage_confidence: Optional[float] = None


class SOARAdapter(ABC):
    """Abstract base class for SOAR platform adapters."""

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ):
        """Initialize the adapter.

        Args:
            base_url: SOAR platform API URL
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds

        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    @abstractmethod
    def fetch_incidents(
        self,
        limit: int = 100,
        status: Optional[str] = None,
        since: Optional[str] = None,
    ) -> list[SOARIncident]:
        """Fetch incidents from the SOAR platform.

        Args:
            limit: Maximum number of incidents
            status: Filter by status
            since: Fetch incidents since this timestamp

        Returns:
            List of SOARIncident objects

        """
        pass

    @abstractmethod
    def update_incident(
        self,
        incident_id: str,
        triage_result: dict[str, Any],
    ) -> bool:
        """Update an incident with triage results.

        Args:
            incident_id: The incident ID
            triage_result: Triage prediction results

        Returns:
            True if update was successful

        """
        pass

    @abstractmethod
    def create_incident(
        self,
        alert: dict[str, Any],
        triage_result: dict[str, Any],
    ) -> str:
        """Create a new incident from an alert with triage.

        Args:
            alert: The alert data
            triage_result: Triage prediction results

        Returns:
            Created incident ID

        """
        pass

    def format_triage_note(self, triage_result: dict[str, Any]) -> str:
        """Format triage result as a note/comment.

        Args:
            triage_result: Triage prediction dictionary

        Returns:
            Formatted note text

        """
        note = f"""## Kodiak SecOps 1 Triage Analysis

**Decision:** {triage_result.get('decision', 'N/A').upper()}
**Priority:** {triage_result.get('priority', 'N/A')}/5
**Confidence:** {triage_result.get('confidence', 0) * 100:.0f}%
**Escalation Required:** {'Yes' if triage_result.get('escalation_required') else 'No'}

### Reasoning
{triage_result.get('reasoning', 'N/A')}

### Recommended Actions
"""
        for i, action in enumerate(triage_result.get("recommended_actions", []), 1):
            note += f"{i}. {action}\n"

        if triage_result.get("escalation_target"):
            note += f"\n**Escalation Target:** {triage_result['escalation_target']}"

        note += "\n\n---\n_Automated analysis by Kodiak SecOps 1_"

        return note


class XSOARAdapter(SOARAdapter):
    """Adapter for Palo Alto XSOAR (Demisto).

    Implements the XSOAR API for incident management and enrichment.

    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        api_key_id: Optional[str] = None,
        **kwargs,
    ):
        """Initialize XSOAR adapter.

        Args:
            base_url: XSOAR server URL
            api_key: API key
            api_key_id: API key ID (for XSOAR 8+)

        """
        super().__init__(base_url, api_key, **kwargs)
        self.api_key_id = api_key_id

    def _get_headers(self) -> dict[str, str]:
        """Get authentication headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.api_key:
            if self.api_key_id:
                headers["x-xdr-auth-id"] = self.api_key_id
                headers["Authorization"] = self.api_key
            else:
                headers["Authorization"] = self.api_key
        return headers

    def fetch_incidents(
        self,
        limit: int = 100,
        status: Optional[str] = None,
        since: Optional[str] = None,
    ) -> list[SOARIncident]:
        """Fetch incidents from XSOAR."""
        try:
            import requests
        except ImportError as e:
            raise ImportError("requests package required") from e

        endpoint = f"{self.base_url}/incidents/search"

        query_filter = {}
        if status:
            query_filter["status"] = status
        if since:
            query_filter["fromDate"] = since

        payload = {
            "filter": query_filter,
            "size": limit,
            "sort": [{"field": "created", "asc": False}],
        }

        response = requests.post(
            endpoint,
            headers=self._get_headers(),
            json=payload,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        data = response.json()
        incidents = []

        for item in data.get("data", []):
            incident = SOARIncident(
                incident_id=item.get("id", ""),
                name=item.get("name", ""),
                severity=self._map_severity(item.get("severity", 0)),
                status=item.get("status", ""),
                description=item.get("details", ""),
                labels=[label.get("value", "") for label in item.get("labels", [])],
                raw_data=item,
            )
            incidents.append(incident)

        return incidents

    def update_incident(
        self,
        incident_id: str,
        triage_result: dict[str, Any],
    ) -> bool:
        """Update incident with triage results."""
        try:
            import requests
        except ImportError as e:
            raise ImportError("requests package required") from e

        # Add work note
        note_endpoint = f"{self.base_url}/entry/note"
        note_payload = {
            "id": incident_id,
            "data": self.format_triage_note(triage_result),
            "markdown": True,
        }

        response = requests.post(
            note_endpoint,
            headers=self._get_headers(),
            json=note_payload,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        # Update custom fields
        update_endpoint = f"{self.base_url}/incident"
        update_payload = {
            "id": incident_id,
            "customFields": {
                "kodiak_decision": triage_result.get("decision"),
                "kodiak_priority": triage_result.get("priority"),
                "kodiak_confidence": triage_result.get("confidence"),
                "kodiak_escalation": triage_result.get("escalation_required"),
            },
        }

        response = requests.post(
            update_endpoint,
            headers=self._get_headers(),
            json=update_payload,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        return True

    def create_incident(
        self,
        alert: dict[str, Any],
        triage_result: dict[str, Any],
    ) -> str:
        """Create new incident in XSOAR."""
        try:
            import requests
        except ImportError as e:
            raise ImportError("requests package required") from e

        endpoint = f"{self.base_url}/incident"

        payload = {
            "name": alert.get("title", "Kodiak SecOps Alert"),
            "type": "Kodiak SecOps",
            "severity": self._reverse_map_severity(triage_result.get("priority", 3)),
            "details": alert.get("description", ""),
            "labels": [{"type": "kodiak", "value": triage_result.get("decision", "")}],
            "customFields": {
                "kodiak_decision": triage_result.get("decision"),
                "kodiak_priority": triage_result.get("priority"),
                "kodiak_confidence": triage_result.get("confidence"),
                "kodiak_escalation": triage_result.get("escalation_required"),
                "original_alert": json.dumps(alert),
            },
            "rawJSON": json.dumps(alert),
        }

        response = requests.post(
            endpoint,
            headers=self._get_headers(),
            json=payload,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        return str(response.json().get("id", ""))

    def _map_severity(self, xsoar_severity: int) -> str:
        """Map XSOAR severity (0-4) to string."""
        mapping = {
            0: "informational",
            1: "low",
            2: "medium",
            3: "high",
            4: "critical",
        }
        return mapping.get(xsoar_severity, "medium")

    def _reverse_map_severity(self, priority: int) -> int:
        """Map priority (1-5) to XSOAR severity (0-4)."""
        mapping = {1: 4, 2: 3, 3: 2, 4: 1, 5: 0}
        return mapping.get(priority, 2)


class SplunkSOARAdapter(SOARAdapter):
    """Adapter for Splunk SOAR (Phantom).

    Implements the Splunk SOAR REST API for container management.

    """

    def fetch_incidents(
        self,
        limit: int = 100,
        status: Optional[str] = None,
        since: Optional[str] = None,
    ) -> list[SOARIncident]:
        """Fetch containers from Splunk SOAR."""
        try:
            import requests
        except ImportError as e:
            raise ImportError("requests package required") from e

        endpoint = f"{self.base_url}/rest/container"

        params: dict[str, str] = {
            "page_size": str(limit),
            "sort": "create_time",
            "order": "desc",
        }
        if status:
            params["_filter_status"] = f'"{status}"'

        response = requests.get(
            endpoint,
            headers=self._get_headers(),
            params=params,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        data = response.json()
        incidents = []

        for item in data.get("data", []):
            incident = SOARIncident(
                incident_id=str(item.get("id", "")),
                name=item.get("name", ""),
                severity=item.get("severity", "medium"),
                status=item.get("status", ""),
                description=item.get("description", ""),
                labels=[item.get("label", "")],
                raw_data=item,
            )
            incidents.append(incident)

        return incidents

    def update_incident(
        self,
        incident_id: str,
        triage_result: dict[str, Any],
    ) -> bool:
        """Update container with triage results."""
        try:
            import requests
        except ImportError as e:
            raise ImportError("requests package required") from e

        # Add note
        note_endpoint = f"{self.base_url}/rest/container/{incident_id}/note"
        note_payload = {
            "content": self.format_triage_note(triage_result),
            "title": "Kodiak SecOps 1 Analysis",
        }

        response = requests.post(
            note_endpoint,
            headers=self._get_headers(),
            json=note_payload,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        # Update container fields
        update_endpoint = f"{self.base_url}/rest/container/{incident_id}"
        update_payload = {
            "custom_fields": {
                "kodiak_decision": triage_result.get("decision"),
                "kodiak_priority": triage_result.get("priority"),
            },
        }

        response = requests.post(
            update_endpoint,
            headers=self._get_headers(),
            json=update_payload,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        return True

    def create_incident(
        self,
        alert: dict[str, Any],
        triage_result: dict[str, Any],
    ) -> str:
        """Create new container in Splunk SOAR."""
        try:
            import requests
        except ImportError as e:
            raise ImportError("requests package required") from e

        endpoint = f"{self.base_url}/rest/container"

        severity_map = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "informational"}

        payload = {
            "name": alert.get("title", "Kodiak SecOps Alert"),
            "label": "kodiak_secops",
            "severity": severity_map.get(triage_result.get("priority", 3), "medium"),
            "description": alert.get("description", ""),
            "data": {
                "alert": alert,
                "triage": triage_result,
            },
            "custom_fields": {
                "kodiak_decision": triage_result.get("decision"),
                "kodiak_priority": triage_result.get("priority"),
                "kodiak_confidence": triage_result.get("confidence"),
            },
        }

        response = requests.post(
            endpoint,
            headers=self._get_headers(),
            json=payload,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        return str(response.json().get("id", ""))

    def _get_headers(self) -> dict[str, str]:
        """Get authentication headers for Splunk SOAR."""
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["ph-auth-token"] = self.api_key
        return headers


class WebhookAdapter(SOARAdapter):
    """Generic webhook adapter for custom integrations.

    Sends triage results to any webhook endpoint.

    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        custom_headers: Optional[dict[str, str]] = None,
        **kwargs,
    ):
        """Initialize webhook adapter.

        Args:
            base_url: Webhook URL
            api_key: Optional API key for Authorization header
            secret_key: Optional secret for HMAC signature
            custom_headers: Additional headers to include

        """
        super().__init__(base_url, api_key, **kwargs)
        self.secret_key = secret_key
        self.custom_headers = custom_headers or {}

    def fetch_incidents(
        self,
        limit: int = 100,
        status: Optional[str] = None,
        since: Optional[str] = None,
    ) -> list[SOARIncident]:
        """Not implemented for webhook adapter."""
        raise NotImplementedError("Webhook adapter does not support fetching incidents")

    def update_incident(
        self,
        incident_id: str,
        triage_result: dict[str, Any],
    ) -> bool:
        """Send triage update via webhook."""
        return self._send_webhook(
            {
                "event": "triage_update",
                "incident_id": incident_id,
                "triage": triage_result,
                "timestamp": time.time(),
            }
        )

    def create_incident(
        self,
        alert: dict[str, Any],
        triage_result: dict[str, Any],
    ) -> str:
        """Send new incident via webhook."""
        self._send_webhook(
            {
                "event": "new_incident",
                "alert": alert,
                "triage": triage_result,
                "timestamp": time.time(),
            }
        )
        return f"webhook_{int(time.time())}"

    def _send_webhook(self, payload: dict[str, Any]) -> bool:
        """Send webhook payload."""
        try:
            import requests
        except ImportError as e:
            raise ImportError("requests package required") from e

        headers = {
            "Content-Type": "application/json",
            **self.custom_headers,
        }

        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body = json.dumps(payload)

        if self.secret_key:
            signature = hmac.new(
                self.secret_key.encode(),
                body.encode(),
                hashlib.sha256,
            ).hexdigest()
            headers["X-Signature"] = f"sha256={signature}"

        response = requests.post(
            self.base_url,
            headers=headers,
            data=body,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        return True


def get_adapter(
    platform: str,
    base_url: str,
    **kwargs,
) -> SOARAdapter:
    """Get appropriate SOAR adapter for the specified platform.

    Args:
        platform: Platform name (xsoar, splunk_soar, webhook)
        base_url: Platform API URL
        **kwargs: Platform-specific arguments

    Returns:
        Configured SOARAdapter instance

    """
    adapters: dict[str, type[SOARAdapter]] = {
        "xsoar": XSOARAdapter,
        "demisto": XSOARAdapter,
        "splunk_soar": SplunkSOARAdapter,
        "phantom": SplunkSOARAdapter,
        "webhook": WebhookAdapter,
    }

    adapter_class = adapters.get(platform.lower())
    if not adapter_class:
        raise ValueError(f"Unknown platform: {platform}. Supported: {list(adapters.keys())}")

    return adapter_class(base_url, **kwargs)
