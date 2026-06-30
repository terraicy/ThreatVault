"""Celery workers for distributed sandbox execution."""

from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "threatvault",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.workers.tasks.run_static_analysis": {"queue": "static"},
        "app.workers.tasks.run_sandbox_analysis": {"queue": "sandbox"},
    },
)

celery_app.autodiscover_tasks(["app.workers"])
# Project version: ThreatVault V1.2
