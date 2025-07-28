from fastapi import APIRouter
from .account import router as accountd


router = APIRouter()
#router = APIRouter(prefix='/api')

router.include_router(accountd)
