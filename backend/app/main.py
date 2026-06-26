import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import PROJECT_ROOT, get_settings
from app.core.database import init_db
from app.core.logging_config import setup_logging

settings = get_settings()
setup_logging(
    log_dir=settings.log_dir,
    level=settings.log_level,
    max_bytes=settings.log_max_bytes,
    backup_count=settings.log_backup_count,
)

logger = logging.getLogger(__name__)
access_logger = logging.getLogger("threatvault.access")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Starting %s v%s", settings.app_name, settings.app_version)
    logger.info("Log directory: %s", settings.log_dir.resolve())
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("Shutting down %s", settings.app_name)


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Malware analysis platform — static + sandbox + ML scoring",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000
        client = request.client.host if request.client else "-"
        access_logger.info(
            '%s %s %s %.1fms',
            client,
            request.method,
            request.url.path,
            duration_ms,
        )
        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router, prefix=settings.api_prefix, tags=["analysis"])

    frontend_dir = PROJECT_ROOT / "frontend"
    if frontend_dir.exists():
        app.mount("/assets", StaticFiles(directory=frontend_dir / "assets"), name="assets")

        @app.get("/")
        async def dashboard():
            return FileResponse(frontend_dir / "index.html")
    else:
        logger.warning("Frontend not found at %s", frontend_dir)

    @app.get("/health")
    async def health():
        return {
            "status": "ok",
            "service": settings.app_name,
            "version": settings.app_version,
        }

    return app


app = create_app()
