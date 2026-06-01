import secrets
from pathlib import Path

# Create .env
with open(".env", "w") as f:
    f.write("SECRET_KEY=" + secrets.token_urlsafe(32) + "\n")
    f.write("MAX_UPLOAD_SIZE=5242880\n")
    f.write("TOKEN_EXP_SECONDS=300\n")
    f.write("RATE_LIMIT_REQUESTS=50\n")
    f.write("RATE_LIMIT_WINDOW_SECONDS=60\n")

# Create demo files
base = Path("scripts/demo_attack_files/malicious_samples")
base.mkdir(parents=True, exist_ok=True)

# Minimal JPEG
(base / "sample.jpg").write_bytes(b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xD9")

# Minimal PDF
(base / "sample.pdf").write_text("%PDF-1.4\n%EOF\n")

# PHP disguised as JPG
(base / "php_shell_disguised.jpg").write_text("<?php echo \"pwned\"; ?>")

# Script file
(base / "tiny_script.txt").write_text("#!/bin/bash\necho \"owned\"\n")

print("Setup complete!")
