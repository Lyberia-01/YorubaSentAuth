from flask import Flask
from database import db
from models import User
from auth_routes import auth
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from flask_cors import CORS
import os

load_dotenv()



def create_app():
    app = Flask(__name__)

    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")

    db.init_app(app)
    JWTManager(app)

    CORS(app)

    app.register_blueprint(auth, url_prefix="/auth")

    with app.app_context():
        db.create_all()

    return app

app = create_app()

if __name__ == '__main__':
    port = os.environ.get('PORT', 5000)
    app.run(port=port, host='0.0.0.0', debug=True)