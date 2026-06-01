from pydantic import BaseModel


class UploadResponse(BaseModel):
    status: str
    id: str
    message: str


class ErrorResponse(BaseModel):
    status: str = "error"
    reason: str


