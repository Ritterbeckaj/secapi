"""REST endpoints for Document / malware static analysis."""
from __future__ import annotations

from fastapi import APIRouter, File, UploadFile

from .service import analyze_document

router = APIRouter()


@router.post("/analyze", summary="Static-analysis a suspicious document (PDF/Office/script)")
async def analyze(file: UploadFile = File(...)) -> dict:
    raw = await file.read()
    result = analyze_document(file.filename or "unnamed", raw)
    return result.to_dict()
