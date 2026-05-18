"""Main agent loop: register, poll for jobs, run checks, report results."""
import logging
import time

from . import config
from .checks import run_check
from .client import ServerClient
from .identity import cert_common_name

log = logging.getLogger("blueeye.agent")


def execute_job(client, job):
    """Run a single job. A failure here is logged and reported, never fatal."""
    job_id = job.get("id")
    log.info("running job %s: %s -> %s", job_id, job.get("type"), job.get("target"))
    try:
        data = run_check(job)
        client.submit_result(job_id, "ok", data=data)
        log.info("job %s completed", job_id)
    except Exception as exc:
        # A single test failure must not crash the agent: log and continue.
        log.error("job %s failed: %s", job_id, exc)
        try:
            client.submit_result(job_id, "error", error=str(exc))
        except Exception as report_exc:
            log.error("could not report failure for job %s: %s", job_id, report_exc)


def run_forever():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        cn = cert_common_name(config.CLIENT_CERT)
        log.info("agent identity (cert CN): %s", cn)
    except Exception as exc:
        log.warning("could not read client certificate CN: %s", exc)

    client = ServerClient()

    agent_id = None
    while agent_id is None:
        try:
            agent = client.register()
            agent_id = agent["id"]
            log.info(
                "registered as '%s' (location=%s, connection=%s)",
                agent_id,
                agent.get("location"),
                agent.get("connection"),
            )
        except Exception as exc:
            log.error("registration failed, retrying in %ss: %s", config.POLL_INTERVAL, exc)
            time.sleep(config.POLL_INTERVAL)

    log.info("polling for jobs every %ss", config.POLL_INTERVAL)
    while True:
        try:
            jobs = client.poll_jobs(agent_id)
            if jobs:
                log.info("received %d job(s)", len(jobs))
            for job in jobs:
                execute_job(client, job)
        except Exception as exc:
            # Network/server hiccup: log and keep the agent alive.
            log.error("poll cycle failed: %s", exc)
        time.sleep(config.POLL_INTERVAL)
