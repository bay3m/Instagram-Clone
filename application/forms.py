from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, EmailField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=6)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=1)])
    bio      = StringField("bio", validators=[DataRequired()])
    submit   = SubmitField("login")

class SignUpForm(FlaskForm):
    username         = StringField("Username", validators=[DataRequired(), Length(min=6)])
    password         = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password", message="password must match")])
    submit           = SubmitField("sign up")  

class EditProfile(FlaskForm):
     bio         = StringField("bio", validators=[DataRequired()])
     profile_pic = FileField("profile_pic", validators=[DataRequired()])
     submit      = SubmitField("save")

class CreatedPost(FlaskForm):
    photo    = FileField("photo", validators=[DataRequired()])
    caption  = StringField("caption", validators=[DataRequired()])
    submit   = SubmitField("create")

class EditPost(FlaskForm):
    caption  = StringField("caption", validators=[DataRequired(), Length(min=2)])
    submit   = SubmitField("edit")