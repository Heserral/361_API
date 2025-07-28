from pydantic import BaseModel
from typing import List

class ReportVR(BaseModel):
    sceneid: int
    serial: str
    appid:str

class AuthVR(BaseModel):
    serial  : str
    regid: str