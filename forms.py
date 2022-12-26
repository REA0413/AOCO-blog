from flask_ckeditor import CKEditorField
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, validators
from wtforms.validators import DataRequired, URL


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = EmailField("Your Email", [validators.Email(message="Invalid email address", allow_empty_local=False)])
    password = PasswordField("Your Password",
                             [validators.Length(min=9, max=30, message="Field must be at least 9 characters long.")])
    name = StringField("Your Name", validators=[DataRequired()])
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    email = EmailField("Your Email", [validators.Email(message="Invalid email address", allow_empty_local=False)])
    password = PasswordField("Your Password",
                             [validators.Length(min=9, max=30, message="Field must be at least 9 characters long.")])
    submit = SubmitField("Submit")

class CommentForm(FlaskForm):
    body = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
