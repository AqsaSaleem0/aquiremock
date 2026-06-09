import json
import logging
import time
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
import redis.asyncio as aioredis
import os

from app.security.crypto import generate_secure_otp
from app.services.smtp_service import send_otp_email

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["authentication"])

OTP_EXPIRY = 600   # 10 minutes (1000 seconds bohat zyada tha)
MAX_ATTEMPTS = 5

# Redis client
redis_client = aioredis.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379"),
    decode_responses=True
)

class EmailRequest(BaseModel):
    email: str

class VerifyCodeRequest(BaseModel):
    email: str
    code: str


@router.post("/send-code")
async def auth_send_code(req: EmailRequest, background_tasks: BackgroundTasks):
    code = str(generate_secure_otp())
    
    data = json.dumps({"code": code, "attempts": 0})
    
    # Redis mein store karo with expiry
    await redis_client.setex(f"otp:{req.email}", OTP_EXPIRY, data)
    
    logger.info(f"OTP stored for {req.email}")
    background_tasks.add_task(send_otp_email, req.email, code)
    return {"status": "sent", "message": "Code sent"}


@router.post("/verify-code")
async def auth_verify_code(req: VerifyCodeRequest):
    key = f"otp:{req.email}"
    raw = await redis_client.get(key)
    
    logger.info(f"Verifying code for {req.email}")

    if not raw:
        logger.warning(f"Code expired or not found for {req.email}")
        raise HTTPException(400, "Code expired or not found")

    data = json.loads(raw)
    code = data["code"]
    attempts = data["attempts"]

    if attempts >= MAX_ATTEMPTS:
        await redis_client.delete(key)
        raise HTTPException(429, "Too many attempts. Request a new code.")

    if str(code) != str(req.code).strip():
        # Attempts increment karo
        data["attempts"] = attempts + 1
        ttl = await redis_client.ttl(key)  # remaining time preserve karo
        await redis_client.setex(key, ttl, json.dumps(data))
        
        logger.warning(f"Invalid code attempt for {req.email}")
        raise HTTPException(400, "Invalid code")

    # Success — delete karo
    await redis_client.delete(key)
    logger.info(f"Verified successfully: {req.email}")
    return {"status": "ok", "message": "Verified"}