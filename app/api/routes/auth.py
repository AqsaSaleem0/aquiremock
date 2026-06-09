import logging
import time
from typing import Dict, Tuple
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.security.crypto import generate_secure_otp
from app.services.smtp_service import send_otp_email

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/auth",
    tags=["authentication"],
)

OTP_EXPIRY = 300
MAX_ATTEMPTS = 5

login_store: Dict[str, Tuple[str, float, int]] = {}

class EmailRequest(BaseModel):
    email: str

class VerifyCodeRequest(BaseModel):
    email: str
    code: str


@router.post("/send-code")
async def auth_send_code(req: EmailRequest, background_tasks: BackgroundTasks):
    code = generate_secure_otp()
    login_store[req.email] = (str(code), time.time() + OTP_EXPIRY, 0)
    logger.info(f"OTP stored for {req.email}: '{str(code)}'")
    background_tasks.add_task(send_otp_email, req.email, code)
    return {"status": "sent", "message": "Code sent"}


@router.post("/verify-code")
async def auth_verify_code(req: VerifyCodeRequest):
    stored = login_store.get(req.email)
    logger.info(f"Verifying for {req.email} | stored={stored} | received='{req.code}'")

    if not stored:
        raise HTTPException(400, "Code expired or not found")

    code, expiry, attempts = stored

    if time.time() > expiry:
        del login_store[req.email]
        raise HTTPException(400, "Code expired")

    if attempts >= MAX_ATTEMPTS:
        del login_store[req.email]
        raise HTTPException(429, "Too many attempts. Request a new code.")

    if str(code) != str(req.code).strip():
        login_store[req.email] = (code, expiry, attempts + 1)
        logger.warning(f"Wrong code for {req.email}: expected='{code}' got='{req.code}'")
        raise HTTPException(400, "Invalid code")

    del login_store[req.email]
    logger.info(f"Verified successfully: {req.email}")
    return {"status": "ok", "message": "Verified"}