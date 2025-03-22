from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flasgger import Swagger

db = SQLAlchemy()

app = Flask(__name__)

# Configure SQLite database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///keys.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)  # Initialize after app is created

app.config['SWAGGER'] = {
    'title': 'Encryption and Hashing API',
    'uiversion': 3
}

swagger = Swagger(app)  # Add Swagger

with app.app_context():
    from app.database import SymmetricKey, AsymmetricKey
    db.create_all()  # Ensures tables are created

from app import routes