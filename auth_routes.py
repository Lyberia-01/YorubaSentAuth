from flask import Blueprint, request, jsonify
from models import User, History
from database import db
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
import re
from datetime import datetime

auth = Blueprint('auth', __name__)
bcrypt = Bcrypt()

@auth.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    fullname = data.get('fullname')
    email = data.get('email')
    password = data.get('password')

    if not fullname or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 409

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(fullname=fullname, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({'token': access_token, 'user': {'fullname': user.fullname, 'email': user.email}})

@auth.route('/history', methods=['POST', 'GET'])
def history():
    if request.method == 'POST':
        data = request.get_json()
        user_email = data.get("email")
        print(user_email)
        print(data)
        # Check if email and sentiment data is provided
        if not user_email or not all(k in data for k in ["sentiment_text", "sentiment", "sentiment_score"]):
            return jsonify({'error': 'Missing data fields'}), 400

        # Find the user by email
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Create history entry using the user's ID
        new_history = History(
            user_id=user.id,
            sentiment_text=data.get("sentiment_text"),
            sentiment=data.get("sentiment"),
            sentiment_score=data.get("sentiment_score")
        )
        
        db.session.add(new_history)
        db.session.commit()
        return jsonify({'message': 'History saved successfully'}), 201

    elif request.method == 'GET':
        # Get the email from the URL query parameter
        user_email = request.args.get("email")
        if not user_email:
            return jsonify({'error': 'Email is required'}), 400

        # Find the user by email
        user = User.query.filter_by(email=user_email).first()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Fetch history using the user's ID
        user_history = History.query.filter_by(user_id=user.id).order_by(History.date_time.desc()).all()
        
        if not user_history:
            return jsonify({'message': 'No history found for this user'}), 200

        history_list = []
        for entry in user_history:
            history_list.append({
                'id': entry.id,
                'date_time': entry.date_time.isoformat(),
                'sentiment_text': entry.sentiment_text,
                'sentiment': entry.sentiment,
                'sentiment_score': entry.sentiment_score
            })
        
        return jsonify(history_list), 200
    
@auth.route('/history/<int:id>', methods=['DELETE'])
def delete_history_entry(id):
    # Find the history entry by its ID
    history_entry = History.query.get(id)

    # If the entry doesn't exist, return a 404 error
    if not history_entry:
        return jsonify({"message": "History entry not found"}), 404

    try:
        # Delete the entry from the database
        db.session.delete(history_entry)
        db.session.commit()
        return jsonify({"message": "History entry deleted successfully"}), 200
    except Exception as e:
        # Handle potential errors during deletion
        db.session.rollback()
        return jsonify({"message": "Error deleting history entry", "error": str(e)}), 500

@auth.route('/google-login', methods=['POST'])
def google_login():
    data = request.get_json()
    email = data.get('email')
    fullname = data.get('fullname')

    if not email or not fullname:
        return jsonify({'error': 'Email and fullname are required'}), 400

    # Find the user by email
    user = User.query.filter_by(email=email).first()

    if not user:
        # If the user doesn't exist, create a new one
        new_user = User(fullname=fullname, email=email, password='google-user-password') # A placeholder password
        db.session.add(new_user)
        db.session.commit()
        user = new_user

    # Return the user data to the frontend for local storage
    return jsonify({
        "message": "Successfully logged in with Google",
        "user": {
            "fullname": user.fullname,
            "email": user.email
        }
    }), 200