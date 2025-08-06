from database import db
from datetime import datetime, timezone

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname=db.Column(db.String(100), nullable=False)
    email=db.Column(db.String(120), nullable=False, unique=True)
    password=db.Column(db.String(200), nullable=False)
    created_at=db.Column(db.DateTime, default=datetime.now(timezone.utc))