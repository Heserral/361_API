from fastapi import APIRouter, Request, HTTPException
from core.db import MySQLManager
from core.logger import logger
from models.vr import ReportVR, AuthVR


router = APIRouter()

@router.post("/reportvrstate",tags=["VR"])
async def reportvrstate(request:Request,body:ReportVR):
  user_info = request.state.user
  return user_info

@router.post("/registervr",tags=["VR"])
async def registervr(request:Request,body:AuthVR):
  user_info = request.state.user
  return user_info