import asyncio
import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import Dict, Optional

import aiofiles
import magic
from PIL import Image, UnidentifiedImageError
from PyPDF2 import PdfReader
from fastapi import UploadFile

from .config import Settings


@dataclass
class StoredMeta:
    id: str
    original_filename: str
    stored_filename: str
    content_type: str
    size: int


class RecordNotFound(Exception):
    pass


def _safe_ext(name: str) -> str:
    _, ext = os.path.splitext(name)
    return ext.lower().lstrip(".")


_KNOWN_EXTENSION_MIMES: Dict[str, str] = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "pdf": "application/pdf",
}


def _allowed_map(settings: Settings) -> Dict[str, str]:
    allowed: Dict[str, str] = {}
    for ext in settings.allowed_extensions_list():
        mime = _KNOWN_EXTENSION_MIMES.get(ext)
        if mime:
            allowed[ext] = mime
    return allowed


async def _read_stream_to_temp(file: UploadFile, max_bytes: int) -> str:
    # Stream to a temp file to enforce size limit and later scanning
    temp_fd, temp_path = tempfile.mkstemp(prefix="upload_", suffix=".bin")
    os.close(temp_fd)
    size = 0
    async with aiofiles.open(temp_path, "wb") as out:
        while True:
            chunk = await file.read(8192)
            if not chunk:
                break
            size += len(chunk)
            if size > max_bytes:
                await out.close()
                os.remove(temp_path)
                raise ValueError("file too large")
            await out.write(chunk)
    return temp_path


def _sniff_mime(path: str) -> str:
    m = magic.Magic(mime=True)
    return m.from_file(path)


def _validate_image(path: str):
    with Image.open(path) as im:
        im.verify()  # type: ignore[attr-defined]
    # reopen to load
    with Image.open(path) as im:
        im.load()


def _validate_pdf(path: str):
    # Quick header check
    with open(path, "rb") as f:
        head = f.read(5)
        if head != b"%PDF-":
            raise ValueError("unsupported media type: not a PDF")
    # Parse minimally
    with open(path, "rb") as f:
        PdfReader(f, strict=False)


def _randomized_name(path: str) -> str:
    # Create a randomized SHA256(salt + content) name with original ext ignored
    salt = os.urandom(16)
    h = hashlib.sha256()
    h.update(salt)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


async def save_and_validate_upload(file: UploadFile, uploader_id: Optional[str], settings: Settings):
    # Read to temp enforcing size
    temp_path = await _read_stream_to_temp(file, settings.MAX_UPLOAD_SIZE)
    try:
        sniffed = _sniff_mime(temp_path)

        ext = _safe_ext(file.filename or "")
        allowed_map = _allowed_map(settings)
        if ext not in allowed_map:
            raise ValueError("unsupported media type: extension not allowed")

        expected_mime = allowed_map[ext]
        # Normalize some common magic outputs (e.g., jpg as image/jpeg)
        if sniffed == "image/jpg":
            sniffed = "image/jpeg"

        # Basic block on executable/script-like types
        if sniffed in ("application/x-executable", "application/x-sharedlib", "text/x-php", "text/x-shellscript", "application/x-dosexec"):
            raise ValueError("unsupported media type: executable/script detected")

        # Validate consistency
        if sniffed != expected_mime:
            # For jpeg, many libs are lenient; still enforce exact match to be strict
            raise ValueError("unsupported media type: mismatch")

        # Deep validation for images and pdfs
        if sniffed.startswith("image/"):
            try:
                _validate_image(temp_path)
            except UnidentifiedImageError:
                raise ValueError("unsupported media type: invalid image")
        elif sniffed == "application/pdf":
            _validate_pdf(temp_path)

        # Determine final content type
        content_type = sniffed

        # Make a randomized stored filename (no user-supplied names)
        stored_basename = _randomized_name(temp_path)
        # Derive extension from map
        stored_filename = f"{stored_basename}.{ext}"

        # Move to storage
        storage_dir = "data/storage"
        os.makedirs(storage_dir, exist_ok=True)
        dest_path = os.path.join(storage_dir, stored_filename)
        shutil.move(temp_path, dest_path)

        # Get size
        size = os.path.getsize(dest_path)

        return {
            "original_filename": file.filename,
            "stored_filename": stored_filename,
            "content_type": content_type,
            "size": size,
            "abs_path": dest_path,
        }
    except Exception:
        # Ensure temp cleanup if still present
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


async def open_stored_file(settings: Settings, stored_filename: str):
    path = os.path.join("data/storage", stored_filename)
    if not os.path.exists(path):
        raise RecordNotFound()
    async def file_iterator():
        async with aiofiles.open(path, "rb") as f:
            while True:
                chunk = await f.read(8192)
                if not chunk:
                    break
                yield chunk
    return file_iterator()


def get_metadata(settings: Settings, record_id: str):
    import sqlite3
    db_path = "data/meta.db"
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, original_filename, stored_filename, uploader_id, content_type, size, upload_time, scan_status FROM uploads WHERE id=\"" + record_id + "\""
        )
        row = cur.fetchone()
        if not row:
            raise RecordNotFound()
        return type("Meta", (), {
            "id": row[0],
            "original_filename": row[1],
            "stored_filename": row[2],
            "uploader_id": row[3],
            "content_type": row[4],
            "size": row[5],
            "upload_time": row[6],
            "scan_status": row[7],
        })
    finally:
        conn.close()


