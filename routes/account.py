from fastapi import APIRouter, Request, HTTPException
from core.db import MySQLManager
from core.logger import logger


router = APIRouter()

@router.post("/getpermissions",tags=["Account"])
async def query_app_permissions(request:Request):
  user_info = request.state.user
  return user_info
  