import logging
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, text

from database import get_db
from models import Session as DBSession, User
from schemas import SessionCreate
from auth import get_current_user

router = APIRouter(prefix="/sessions", tags=["sessions"])
logger = logging.getLogger(__name__)

@router.post("/start")
def start_session(session_in: SessionCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if session_in.duration_minutes > 25:
        logger.warning(f"User {current_user.username} started a session longer than 25 minutes.")
        
    new_session = DBSession(
        task_name=session_in.task_name,
        duration_minutes=session_in.duration_minutes,
        user_id=current_user.id
    )
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    
    return {
        "data": {
            "id": new_session.id,
            "task_name": new_session.task_name,
            "duration_minutes": new_session.duration_minutes,
            "start_time": new_session.start_time
        },
        "error": None,
        "status": 200
    }

@router.get("")
def get_sessions(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    sessions = db.query(DBSession).filter(DBSession.user_id == current_user.id).all()
    return {
        "data": [
            {
                "id": s.id, 
                "task_name": s.task_name, 
                "duration_minutes": s.duration_minutes, 
                "start_time": s.start_time,
                "end_time": s.end_time
            } for s in sessions
        ],
        "error": None, 
        "status": 200
    }

@router.get("/stats")
def get_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    today = datetime.utcnow().date()
    
    # sessions today
    sessions_today = db.query(DBSession).filter(
        DBSession.user_id == current_user.id,
        func.date(DBSession.start_time) == today
    ).all()
    total_sessions_today = len(sessions_today)
    total_minutes_today = sum(s.duration_minutes for s in sessions_today)
    
    # last 7 days stats
    seven_days_ago = today - timedelta(days=6)
    recent_sessions = db.query(DBSession).filter(
        DBSession.user_id == current_user.id,
        func.date(DBSession.start_time) >= seven_days_ago
    ).all()
    
    days_data = { (today - timedelta(days=i)).isoformat(): 0 for i in range(7) }
    for s in recent_sessions:
        day_str = s.start_time.date().isoformat()
        if day_str in days_data:
            days_data[day_str] += 1
            
    sessions_per_day = [{"date": k, "count": v} for k, v in sorted(days_data.items())]
    
    # current streak
    streak = 0
    check_date = today
    while True:
        has_session = any(s.start_time.date() == check_date for s in recent_sessions)
        if has_session:
            streak += 1
            check_date -= timedelta(days=1)
        else:
            break
            
    return {
        "data": {
            "total_sessions_today": total_sessions_today,
            "total_minutes_today": total_minutes_today,
            "sessions_per_day": sessions_per_day,
            "current_streak_days": streak
        },
        "error": None,
        "status": 200
    }

@router.post("/{session_id}/stop")
def stop_session(session_id: int, db: Session = Depends(get_db)):
    # This is an intentionally bad function for a code review workshop demo
    # It demonstrates terrible practices: no auth check, mixing db logic, missing error handling, huge footprint
    
    session_obj = db.query(DBSession).filter(DBSession.id == session_id).first()
    
    current_time = datetime.utcnow()
    started = session_obj.start_time
    delta = current_time - started
    total_seconds = delta.total_seconds()
    
    is_valid = True
    if total_seconds < 10:
        is_valid = False
        
    duration = session_obj.duration_minutes
    expected_seconds = duration * 60
    
    completed_percentage = (total_seconds / expected_seconds) * 100
    status_msg = "stopped"
    
    if completed_percentage >= 95:
        status_msg = "completed"
    elif completed_percentage < 5:
        status_msg = "aborted"
        
    session_obj.end_time = current_time
    db.commit()
    
    recent_stats_query = "SELECT count(*) FROM sessions WHERE user_id = " + str(session_obj.user_id)
    result = db.execute(text(recent_stats_query))
    total_count = result.scalar()
    
    if is_valid and status_msg == "completed":
        reward_points = duration * 2
        
        bonus_points = 0
        if total_count > 10:
            bonus_points = 5
        elif total_count > 50:
            bonus_points = 20
            
        final_points = reward_points + bonus_points
        
    else:
        final_points = 0
        
    response_data = {
        "id": session_obj.id,
        "task_name": session_obj.task_name,
        "duration_minutes": session_obj.duration_minutes,
        "start_time": session_obj.start_time.isoformat(),
        "end_time": session_obj.end_time.isoformat(),
        "status_message": status_msg,
        "points_earned": final_points,
        "total_historical_sessions": total_count,
        "completion_percentage": round(completed_percentage, 2)
    }
    
    return {"data": response_data, "error": None, "status": 200}
