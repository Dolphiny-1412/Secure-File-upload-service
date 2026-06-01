from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response
import os
import aiofiles
from typing import Optional

app = FastAPI(title="vulnerable-service", docs_url="/docs", redoc_url="/redoc")

WEBROOT = os.path.join(os.path.dirname(__file__), "..", "webroot")
UPLOAD_DIR = os.path.abspath(os.path.join(WEBROOT, "uploads"))
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Serve the entire webroot statically at root (intentionally insecure)
app.mount("/", StaticFiles(directory=WEBROOT, html=True), name="static")


@app.post("/upload")
async def upload(file: UploadFile = File(...), uploader_id: Optional[str] = Form(None)):
    # Intentionally insecure: directly trust the client filename
    original_name = file.filename
    dest_path = os.path.join(UPLOAD_DIR, original_name)
    # Ensure upload dir exists
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # Save content without checks
    async with aiofiles.open(dest_path, "wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            await out.write(chunk)

    # Return direct URL
    url = f"/uploads/{original_name}"
    return JSONResponse({"status": "ok", "id": original_name, "message": "uploaded", "url": url})


@app.get("/")
def index():
    # Simple landing with link to uploads
    return Response(
        content='<html><body><h3>vulnerable-service</h3><a href="/uploads/">/uploads/</a></body></html>',
        media_type="text/html",
    )


