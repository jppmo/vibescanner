from fastapi import FastAPI
from sqlalchemy.orm import Session
from . import models

app = FastAPI()

# No auth dependency — vulnerable
@app.get("/users")
async def get_users():
    return db.query(models.User).all()

# No auth dependency — vulnerable
@app.delete("/users/{user_id}")
async def delete_user(user_id: int):
    db.query(models.User).filter(models.User.id == user_id).delete()

# Public — should NOT be flagged
@app.post("/login")
async def login(credentials: LoginRequest):
    return authenticate(credentials)
