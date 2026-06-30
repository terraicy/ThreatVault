# ThreatVault V1.2 Deployment Notes

This public version is prepared for local/demo hosting, not production operation.

## Build

The frontend is static and served by FastAPI.

## Backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Docker

```bash
cd docker
docker compose up --build
```

## Demo Hosting

- Set `THREATVAULT_DEMO_MODE=true`.
- Keep uploads and local databases out of git.
- Public sandbox behavior is simulation mode only.
- Do not host unknown samples without real isolation.
<!-- Project version: ThreatVault V1.2 -->
