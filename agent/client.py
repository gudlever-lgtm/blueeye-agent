"""mTLS HTTP client for talking to the BlueEye server."""
import requests

from . import config


class ServerClient:
    def __init__(self):
        self.base = config.BLUEEYE_SERVER_URL.rstrip("/")
        self.session = requests.Session()
        self.session.cert = (config.CLIENT_CERT, config.CLIENT_KEY)
        self.session.verify = config.CA_CERT
        # Ignore ambient REQUESTS_CA_BUNDLE / proxy env vars so the server is
        # always verified against our CA, not whatever the host has set.
        self.session.trust_env = False

    def register(self):
        """Register/refresh this agent. Identity comes from the client cert CN."""
        resp = self.session.post(
            f"{self.base}/agents/register",
            json={
                "location": config.AGENT_LOCATION,
                "connection": config.AGENT_CONNECTION,
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()

    def poll_jobs(self, agent_id):
        resp = self.session.get(f"{self.base}/agents/{agent_id}/jobs", timeout=15)
        resp.raise_for_status()
        return resp.json().get("jobs", [])

    def submit_result(self, job_id, status, data=None, error=None):
        resp = self.session.post(
            f"{self.base}/jobs/{job_id}/results",
            json={"status": status, "data": data or {}, "error": error},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()
