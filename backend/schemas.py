from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True

class SessionCreate(BaseModel):
    task_name: str
    duration_minutes: int

class SessionResponse(BaseModel):
    id: int
    task_name: str
    duration_minutes: int
    start_time: datetime
    end_time: Optional[datetime] = None
    user_id: int

    class Config:
        from_attributes = True

class SessionStats(BaseModel):
    total_sessions_today: int
    total_minutes_today: int
    sessions_per_day: list[dict]
    current_streak_days: int
