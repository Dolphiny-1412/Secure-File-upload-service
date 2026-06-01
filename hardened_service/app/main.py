import asyncio
import io
import logging
import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.middleware.cors import CORSMiddleware

from .config import Settings, get_settings
from .logging_config import configure_logging
from .storage import (
    save_and_validate_upload,
    open_stored_file,
    get_metadata,
    RecordNotFound,
)
from .scanner import scan_file_and_maybe_quarantine, ClamNotReadyError
from .security import sign_token, verify_token, SecureHeaders
from .db import init_db, insert_record, update_scan_status
from .schemas import UploadResponse, ErrorResponse
from .utils import rate_limiter_dependency

logger = logging.getLogger(__name__)
configure_logging()

app = FastAPI(title="hardened-service", docs_url="/docs", redoc_url="/redoc")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    settings = get_settings()
    init_db(settings)
    logger.info("Service starting with settings: %s", settings.model_dump())


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    reason = exc.detail if isinstance(exc.detail, str) else "error"
    status = "error"
    if exc.status_code == 451:
        status = "quarantined"
    return JSONResponse(
        status_code=exc.status_code,
        content={"status": status, "reason": reason},
    )


@app.post("/upload", response_model=UploadResponse, responses={413: {"model": ErrorResponse}, 415: {"model": ErrorResponse}, 451: {"model": ErrorResponse}, 503: {"model": ErrorResponse}})
async def upload(
    request: Request,
    file: UploadFile = File(...),
    uploader_id: Optional[str] = Form(None),
    settings: Settings = Depends(get_settings),
    _=Depends(rate_limiter_dependency),
):
    # Size limit enforced while reading within storage.save_and_validate_upload
    try:
        stored = await save_and_validate_upload(file=file, uploader_id=uploader_id, settings=settings)
    except ValueError as e:
        msg = str(e)
        if "too large" in msg:
            raise HTTPException(status_code=413, detail="file too large")
        elif "unsupported media type" in msg or "mismatch" in msg:
            raise HTTPException(status_code=415, detail="unsupported media type")
        else:
            raise HTTPException(status_code=400, detail=msg)

    record_id = insert_record(settings, stored["original_filename"], stored["stored_filename"], uploader_id, stored["content_type"], stored["size"], "pending")
    logger.info("Uploaded file stored as id=%s name=%s size=%s", record_id, stored["original_filename"], stored["size"])

    # Scan in-process to provide synchronous decision
    try:
        scan_result = await scan_file_and_maybe_quarantine(settings, stored_path=stored["abs_path"], stored_filename=stored["stored_filename"])
        if scan_result.get("skipped"):
            update_scan_status(settings, record_id, "no_av")
        elif scan_result["infected"]:
            update_scan_status(settings, record_id, "quarantined")
            raise HTTPException(status_code=451, detail="infected")
        update_scan_status(settings, record_id, "clean")
    except ClamNotReadyError:
        logger.error("ClamAV configured but unavailable")
        update_scan_status(settings, record_id, "av_unavailable")
        if os.path.exists(stored["abs_path"]):
            os.remove(stored["abs_path"])
        raise HTTPException(status_code=503, detail="Antivirus service unavailable")
    except Exception as e:
        logger.exception("Scan error: %s", e)
        # Don't fail the upload if scanning fails
        update_scan_status(settings, record_id, "scan_error")
    return UploadResponse(status="ok", id=record_id, message="uploaded")


@app.get("/download/{file_id}")
async def download(
    file_id: str,
    token: str,
    settings: Settings = Depends(get_settings),
    _=Depends(rate_limiter_dependency),
):
    try:
        payload = verify_token(token=token, secret=settings.SECRET_KEY)
        if payload.get("file_id") != file_id:
            raise HTTPException(status_code=403, detail="invalid token")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=403, detail="invalid token")

    try:
        meta = get_metadata(settings, file_id)
    except RecordNotFound:
        raise HTTPException(status_code=404, detail="not found")

    file_stream = await open_stored_file(settings, meta.stored_filename)
    headers = SecureHeaders.build_download_headers(suggested_name=meta.original_filename, content_type=meta.content_type)
    return StreamingResponse(
        file_stream,
        headers=headers,
        media_type=meta.content_type,
    )


@app.get("/")
def index():
    return {"service": "hardened-service", "time": datetime.utcnow().isoformat()}


