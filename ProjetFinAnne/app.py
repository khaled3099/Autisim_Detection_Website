import os

import numpy as np
from PIL import Image
from flask import Flask, render_template, url_for, redirect
from flask_bcrypt import Bcrypt
from flask_login import UserMixin, login_user, LoginManager, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms.fields.simple import StringField, SubmitField, FileField
from wtforms.validators import InputRequired, Length, ValidationError
import tensorflow as tf
loaded_model = tf.keras.models.load_model('Model__.h5')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy()
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db.init_app(app)
app.config['SECRET_KEY'] = 'this is a secret key'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})

    password = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("This username already exists. Please choose a different one.")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Username"})

    password = StringField(validators=[InputRequired(), Length(min=4, max=20)],
                           render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")


class UploadForm(FlaskForm):
    image = FileField(validators=[InputRequired()])
    submit = SubmitField("Upload")



@app.route('/')
def home():
    return render_template('home.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UploadForm()
    r = None
    if form.validate_on_submit():
        img_file = form.image.data
        img = Image.open(img_file)

        # Preprocess the image as needed
        img = img.resize((224, 224))  # Resize image if necessary
        img_array = np.array(img)
        img_array = img_array / 255.0  # Normalize pixel values to [0, 1]
        img_array = np.expand_dims(img_array, axis=0)  # Add batch dimension

        # Make prediction
        prediction_result = loaded_model.predict(img_array)
        if prediction_result>0.5:
            r=str(1-float(prediction_result))+'% ( Normal )'
        else:
            r=str(1-float(prediction_result))+'% ( Autistic )'

    return render_template('dashboard.html', form=form,r=r)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
