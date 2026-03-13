#!/usr/bin/env bash
set -euo pipefail

cd backend

if [ -f package-lock.json ]; then
  npm ci --omit=dev
else
  npm install --omit=dev
fi

exec npm start
