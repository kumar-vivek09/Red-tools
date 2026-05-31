"""Pydantic models for the ARCHAI X backend API."""

from pydantic import BaseModel


class ScanRequest(BaseModel):
    target: str
    scan_level: int = 1


class MalwareUploadRequest(BaseModel):
    filename: str
    content_base64: str


class SandboxRequest(BaseModel):
    sample_id: str
    network_mode: str = "isolated"


class AIRequest(BaseModel):
    prompt: str
    context: dict | None = None
