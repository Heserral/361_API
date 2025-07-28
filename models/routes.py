from pydantic import BaseModel
from typing import List

class Route(BaseModel):
    id: int | None = None  # Optional if not always present
    path: str
    roles: List[str]  # Assuming roles is a list of strings