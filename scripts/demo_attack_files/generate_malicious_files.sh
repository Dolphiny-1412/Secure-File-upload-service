#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$DIR/malicious_samples"
mkdir -p "$OUT"

# Benign sample.jpg (tiny binary header + text, acceptable for demo but magic may not parse as real JPEG; we create a valid minimal JPEG)
# Create a 1x1 pixel JPEG using Python Pillow if available; fallback to header + data
python - <<'PY' || true
from PIL import Image
img = Image.new("RGB", (1,1), color=(255,0,0))
img.save("sample.jpg", "JPEG")
PY
if [ -f "sample.jpg" ]; then mv sample.jpg "$OUT/sample.jpg"; else
  printf "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xD9" > "$OUT/sample.jpg"
fi

# Benign sample.pdf
cat > "$OUT/sample.pdf" <<'PDF'
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>
endobj
xref
0 4
0000000000 65535 f 
0000000010 00000 n 
0000000061 00000 n 
0000000120 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
180
%%EOF
PDF

# Malicious disguised as jpg (php webshell content)
cat > "$OUT/php_shell_disguised.jpg" <<'PHPS'
<?php echo 'pwned'; ?>
PHPS

# Tiny script masquerading as text
cat > "$OUT/tiny_script.txt" <<'SH'
#!/bin/bash
echo "owned"
SH

echo "Generated files in $OUT:"
ls -l "$OUT"


