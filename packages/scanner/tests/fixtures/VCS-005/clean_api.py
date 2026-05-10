from fastapi import Depends, FastAPI
from app.auth import get_current_user
from app.models import User

app = FastAPI()

# Protected by Depends
@app.get("/users")
async def get_users(current_user: User = Depends(get_current_user)):
    return db.query(User).all()

# Protected by Depends
@app.delete("/users/{user_id}")
async def delete_user(user_id: int, current_user: User = Depends(get_current_user)):
    db.query(User).filter(User.id == user_id).delete()

# Public — no auth needed
@app.post("/login")
async def login(credentials: LoginRequest):
    return authenticate(credentials)
