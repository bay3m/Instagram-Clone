from flask import Flask
from flask_sqlalchemy import SQLAlchemy
# from flask_session import Session
from flask_login import LoginManager
from dotenv import load_dotenv
from flask_cors import CORS
import os
from datetime import timedelta
from flask_migrate import Migrate

load_dotenv()

app = Flask(__name__, template_folder = "views")
app.config["SECRET_KEY"] = "SECRET"  #os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"  #os.getenv("DB_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)


# Session(app)
db = SQLAlchemy(app) 
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"
cors = CORS(app)

from application import routes
from application.models import *