from pydantic import BaseModel
from typing import List

class UserAuth(BaseModel):
    id: int | None = None  # Optional if not always present
    email: str
    roles: List[str]  # Assuming roles is a list of strings