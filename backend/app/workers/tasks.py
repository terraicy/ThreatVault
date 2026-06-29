"""Distributed analysis tasks."""

from app.services.sandbox.executor import run_sandbox
from app.services.static.analyzer import analyze_static
from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.tasks.run_static_analysis", bind=True)
def run_static_analysis(self, file_data: bytes, filename: str):
    result = analyze_static(file_data, filename)
    return result.model_dump()


@celery_app.task(name="app.workers.tasks.run_sandbox_analysis", bind=True)
def run_sandbox_analysis(self, file_data: bytes, static_result: dict):
    from app.models.schemas import StaticAnalysisResult

    static = StaticAnalysisResult(**static_result)
    sandbox = run_sandbox(file_data, static)
    return sandbox.model_dump()


@celery_app.task(name="app.workers.tasks.run_full_pipeline", bind=True)
def run_full_pipeline(self, file_data: bytes, filename: str):
    static = analyze_static(file_data, filename)
    sandbox = run_sandbox(file_data, static)
    return {
        "static": static.model_dump(),
        "sandbox": sandbox.model_dump(),
    }
# Project version: ThreatVault V1.1
