import logging
from datetime import datetime, timedelta
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

# email -> (otp_code, expiry_time)
login_store: Dict[str, Tuple[str, datetime]] = {}


class EmailRequest(BaseModel):
    email: str


class VerifyCodeRequest(BaseModel):
    email: str
    code: str


@router.post("/send-code")
async def auth_send_code(req: EmailRequest, background_tasks: BackgroundTasks):
    logger.info(f"Auth code requested for {req.email}")
    code = generate_secure_otp()
    login_store[req.email] = (code, datetime.now() + timedelta(minutes=10))
    background_tasks.add_task(send_otp_email, req.email, code)
    return {"status": "sent", "message": "Code sent"}


@router.post("/verify-code")
async def auth_verify_code(req: VerifyCodeRequest):
    logger.info(f"Verifying code for {req.email}")
    stored = login_store.get(req.email)

    if not stored:
        logger.warning(f"Code expired or not found for {req.email}")
        raise HTTPException(400, "Code expired or not found")

    code, expiry = stored

    if datetime.now() > expiry:
        del login_store[req.email]
        logger.warning(f"Code expired for {req.email}")
        raise HTTPException(400, "Code expired")

    if code != req.code:
        logger.warning(f"Invalid code attempt for {req.email}")
        raise HTTPException(400, "Invalid code")

    del login_store[req.email]
    logger.info(f"User {req.email} verified successfully")
    return {"status": "ok", "message": "Verified"}