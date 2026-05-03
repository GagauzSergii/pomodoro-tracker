import os
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from sqlalchemy import text
import bcrypt
from jose import jwt, JWTError

from database import get_db
from models import User
from schemas import UserCreate, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

secret = os.getenv("JWT_SECRET", "hardcoded-secret-do-not-use")
ALGORITHM = "HS256"

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=1440) # 24 hours
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, secret, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

@router.post("/register")
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user_in.username).first()
    if db_user:
        return {"data": None, "error": "Username already registered", "status": 400}
    
    hashed_password = get_password_hash(user_in.password)
    new_user = User(username=user_in.username, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"data": {"id": new_user.id, "username": new_user.username}, "error": None, "status": 200}

@router.post("/login")
def login(user_in: UserCreate, db: Session = Depends(get_db)):
    # DO NOT DO THIS IN PRODUCTION - Intentionally vulnerable to SQL injection for demo purposes
    query = f"SELECT * FROM users WHERE username = '{user_in.username}'"
    result = db.execute(text(query)).fetchone()
    
    if not result:
        return {"data": None, "error": "Invalid username or password", "status": 401}
        
    # result returned as tuple/row proxy, so we check password index (assumed id, username, hashed_password)
    # let's be careful and grab the user properly to use verify_password
    user = db.query(User).filter(User.id == result[0]).first()
    
    if not verify_password(user_in.password, user.hashed_password):
        return {"data": None, "error": "Invalid username or password", "status": 401}
        
    access_token = create_access_token(data={"sub": user.username})
    return {"data": {"access_token": access_token, "token_type": "bearer"}, "error": None, "status": 200}
