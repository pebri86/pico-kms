#!/usr/bin/env bash
set -euo pipefail
source .venv/bin/activate
exec uvicorn app.main:app --host "${KMS_HOST:-127.0.0.1}" --port "${KMS_PORT:-8000}"
