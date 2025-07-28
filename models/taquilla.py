from pydantic import BaseModel
from typing import List

class RequestTicket(BaseModel):
    sceneid: int
    serial: str
    appid:str