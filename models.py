from database import db
from datetime import datetime, timezone

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname=db.Column(db.String(100), nullable=False)
    email=db.Column(db.String(120), nullable=False, unique=True)
    password=db.Column(db.String(200), nullable=False)
    created_at=db.Column(db.DateTime, default=datetime.now(timezone.utc))
    history_entries = db.relationship('History', backref='user', lazy=True)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_time = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)
    sentiment_text = db.Column(db.Text, nullable=False)
    sentiment = db.Column(db.String(50), nullable=False)
    sentiment_score = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
