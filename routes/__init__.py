from fastapi import APIRouter

from .vr import router as vrd


router = APIRouter()
#router = APIRouter(prefix='/api')

router.include_router(vrd)
