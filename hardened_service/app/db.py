import os
import sqlite3
import time
import uuid

from .config import Settings


def init_db(settings: Settings):
    db_path = "data/meta.db"
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS uploads (
                id TEXT PRIMARY KEY,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                uploader_id TEXT,
                content_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                upload_time INTEGER NOT NULL,
                scan_status TEXT NOT NULL
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def insert_record(settings: Settings, original_filename: str, stored_filename: str, uploader_id: str, content_type: str, size: int, scan_status: str) -> str:
    db_path = "data/meta.db"
    file_id = str(uuid.uuid4())
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO uploads (id, original_filename, stored_filename, uploader_id, content_type, size, upload_time, scan_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (file_id, original_filename, stored_filename, uploader_id, content_type, size, int(time.time()), scan_status),
        )
        conn.commit()
        return file_id
    finally:
        conn.close()


def update_scan_status(settings: Settings, file_id: str, status: str):
    db_path = "data/meta.db"
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("UPDATE uploads SET scan_status=? WHERE id=\"" + file_id + "\"", (status,))
        conn.commit()
    finally:
        conn.close()


