# AGENTS.md

## Cursor Cloud specific instructions

### Services Overview

| Service | Port | Command |
|---------|------|---------|
| Frontend (Vite) | 8080 | `npm run dev` |
| Backend API (FastAPI) | 8000 | `cd api && PYTHONPATH="/workspace/api:/workspace" uvicorn main:app --host 0.0.0.0 --port 8000 --reload` |

### Running the Frontend

Standard commands from `package.json`: `npm run dev`, `npm run build`, `npm run lint`.

### Running the Backend API

The API was designed for Docker (`/app/` paths). For local development:

1. Create required directories: `sudo mkdir -p /app/data /app/logs /app/scripts /app/temp /app/uploads /app/labs && sudo chmod -R 777 /app`
2. Copy scripts to the expected location: `cp -r /workspace/scripts/* /app/scripts/ && cp -r /workspace/labs/* /app/labs/`
3. Ensure `api/__init__.py` exists (needed for `api.*` package imports in `main.py`).
4. Start with: `cd /workspace/api && PYTHONPATH="/workspace/api:/workspace:$PYTHONPATH" python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload`

### Non-obvious caveats

- **Dual import style in `api/main.py`**: The file mixes bare imports (`from database import db`) and package-prefixed imports (`from api.execution_queue import execution_queue`). Both `PYTHONPATH` entries (`/workspace/api` and `/workspace`) are needed to satisfy both styles.
- **Docker unavailable warning**: `lab_manager.py` will log a Docker connection error at startup. This is expected without Docker and does not block other API functionality.
- **`/app/` hardcoded paths**: `database.py` defaults DB to `/app/data/bofa.db`, `script_executor.py` uses `/app/scripts`, `lab_manager.py` uses `/app/labs`. All require the `/app/` directory structure.
- **Default admin credentials**: `admin` / `admin123` (created automatically by `database.py` on first run).
- **ESLint**: The frontend has ~26 pre-existing lint errors (mostly `@typescript-eslint/no-explicit-any`). `npm run lint` exits with code 1.
- **No automated tests**: The `tests/` directory referenced in `pyproject.toml` does not exist yet. `pytest` will find no tests.
- **Root `requirements.txt`**: Contains heavy ML/forensics dependencies (torch, tensorflow, volatility3, etc.) that are NOT needed for the API. Use `api/requirements.txt` for backend development.
- **`~/.local/bin` on PATH**: Python user-installed binaries (including `uvicorn`) land in `~/.local/bin`, which may not be on PATH by default. Add with `export PATH="$HOME/.local/bin:$PATH"`.
