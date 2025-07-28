from fastapi import APIRouter, Request, HTTPException
from core.db import MySQLManager
from core.logger import logger
from models.taquilla import RequestTicket


router = APIRouter()

@router.post("/requestticket",tags=["Ticket"])
async def requestticket(request:Request,body:RequestTicket):
  user_info = request.state.user
  return user_info