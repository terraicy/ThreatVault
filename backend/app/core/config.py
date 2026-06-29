from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> 4 levels up = project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="THREATVAULT_")

    app_name: str = "ThreatVault"
    app_version: str = "1.1.0"
    debug: bool = True
    demo_mode: bool = True

    api_prefix: str = "/api/v1"
    host: str = "0.0.0.0"
    port: int = 8000

    database_url: str = "sqlite+aiosqlite:///./threatvault.db"
    redis_url: str = "redis://localhost:6379/0"
    cache_ttl_seconds: int = 86400

    upload_dir: Path = Path("./uploads")
    max_upload_mb: int = 100
    yara_rules_dir: Path = PROJECT_ROOT / "rules"
    ml_model_path: Path = Path("./models/malware_classifier.json")

    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    sandbox_timeout_seconds: int = 120
    sandbox_workers: int = 4

    enable_ml: bool = True
    enable_yara: bool = True
    enable_sandbox: bool = True
    enable_cache: bool = True

    log_dir: Path = PROJECT_ROOT / "logs"
    log_level: str = "INFO"
    log_max_bytes: int = 10_485_760
    log_backup_count: int = 5


@lru_cache
def get_settings() -> Settings:
    return Settings()
# Project version: ThreatVault V1.1
