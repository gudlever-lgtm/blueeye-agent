import os

BLUEEYE_SERVER_URL = os.environ.get("BLUEEYE_SERVER_URL", "https://localhost:8443")
CLIENT_CERT = os.environ.get("CLIENT_CERT", "certs/agent-001.crt")
CLIENT_KEY = os.environ.get("CLIENT_KEY", "certs/agent-001.key")
CA_CERT = os.environ.get("CA_CERT", "certs/ca.crt")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "30"))

AGENT_LOCATION = os.environ.get("AGENT_LOCATION", "unknown")
AGENT_CONNECTION = os.environ.get("AGENT_CONNECTION", "unknown")
