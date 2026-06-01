#!/usr/bin/env bash
set -euo pipefail

# Generate samples
python -c "
from pathlib import Path
base = Path('scripts/demo_attack_files/malicious_samples')
base.mkdir(parents=True, exist_ok=True)
(base/'sample.jpg').write_bytes(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xD9')
(base/'sample.pdf').write_text('%PDF-1.4\n%EOF\n')
(base/'php_shell_disguised.jpg').write_text('<?php echo \"pwned\"; ?>')
(base/'tiny_script.txt').write_text('#!/bin/bash\necho \"owned\"\n')
print('Demo files created')
"

# Start services in background
echo "Starting services..."
python start_services.py &
SERVICES_PID=$!

# Wait for services
echo "Waiting for services to be ready..."
TRIES=60
until curl -fsS http://localhost:8001/ >/dev/null 2>&1 || [ $TRIES -le 0 ]; do
  TRIES=$((TRIES-1)); sleep 2
done
TRIES=120
until curl -fsS http://localhost:8000/ >/dev/null 2>&1 || [ $TRIES -le 0 ]; do
  TRIES=$((TRIES-1)); sleep 2
done

# Run tests
pytest -q || (echo "Tests failed"; false)

# Summary
python tests/test_harness.py || true

# Tear down
echo "Stopping services..."
kill $SERVICES_PID 2>/dev/null || true
wait $SERVICES_PID 2>/dev/null || true


