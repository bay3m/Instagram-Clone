from flask_wtf import FlaskForm, RecaptchaField
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, EmailField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo

from application.utils import exists_email, not_exists_email, exists_username

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=6)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=1)])
    submit   = SubmitField("login")

class SignUpForm(FlaskForm):
    username         = StringField("Username", validators=[DataRequired(), Length(min=4, max=12), exists_username])
    fullname         = StringField("Full name", validators=[DataRequired(), Length(min4, max=12)])
    email            = EmailField("Email", validators=[DataRequired(), email(), exists_email])
    password         = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit           = SubmitField("sign up")  

class EditProfileForm(FlaskForm):
    username    = StringField("Username", validators=[DataRequired(), Length(min=4, max=12), exists_username])
    email       = EmailField("Email", validators=[DataRequired(), Email(), exists_email])
    profile_pic = FileField("profile pic", validators=[FileAllowed(["jpg", "png", "jpeg"])])
    password    = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    submit      = SubmitField("update profile")

class ResetPassword(FlaskForm):
    old_password         = PasswordField("Old password", validators=[DataRequired(), Length(min=8)])
    new_password         = PasswordField("New password", validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField("Confirm new password", validators=[DataRequired(), Length(min=8), EqualTo("new_password")])
    submit               = SubmitField("reset password")

class ForgotPasswordForm(FlaskForm):
    email     = EmailField("Email", validators=[DataRequired(), not_exists_email])
    recaptcha = RecaptchaField()
    submit    = SubmitField("send link verification to email")

class VerificationResetPasswordForm(FlaskForm):
    password         = PasswordField("new password", validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField("Confirm new password", validators=[DataRequired(), Length(min=8), EqualTo("password")])
    submit           = SubmitField("reset password")

class CreatedPostForm(FlaskForm):
    post_pic    = FileField("photo", validators=[DataRequired(), FileAllowed(["jpg", "png", "jpeg"])])
    caption     = TextAreaField("caption")
    submit      = SubmitField("post")

class EditPostForm(FlaskForm):
    caption  = StringField("caption")
    submit   = SubmitField("update post")