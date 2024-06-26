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


from flask import render_template, request, jsonify
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    r = None  # Initialize an empty message variable
    message = ''
    if request.method == 'POST':
        if 'image' not in request.files:
            message = 'No file part'
        else:
            file = request.files['image']
            if file.filename == '':
                message = 'No selected file'
            else:
                print("Received image:", file.filename)  # Debugging statement
                # Save the uploaded file
                imgo = Image.open(file)
                img_array = load_and_preprocess_image(imgo)
                print("Image array shape:", img_array.shape)  # Debugging statement
                prediction_result = loaded_model.predict(img_array)
                confidence = 1 - float(prediction_result)
                formatted_confidence = "{:.2f}".format(confidence)  # Format to display only two decimal places

                if prediction_result > 0.5:
                    r = f"{formatted_confidence}% ( Normal )"
                else:
                    r = f"{formatted_confidence}% ( Autistic )"
                print("Prediction result:", r)  # Debugging statement
                message = 'File uploaded successfully'

                # Return the prediction result as JSON
                return jsonify({'result': r, 'message': message})

    # If there's no prediction result yet, return an empty response
    return render_template('dashboard.html')



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


@app.route('/dashboard_2', methods=['GET', 'POST'])
@login_required
def dashboard_2():
    image_dir = 'C:/Users/Famille/Desktop/ProjetPFA/ProjetFinAnne/static/images'
    images = os.listdir(image_dir)

    class_0_images = []
    class_1_images = []

    if request.method == 'POST':
        for img_name in images:
            img_path = os.path.join(image_dir, img_name)
            print("Image Path:", img_path)  # Debug: Print image path

            # Load and preprocess the image
            with Image.open(img_path) as im:
                img = load_and_preprocess_image(im)  # Assuming you have a function for this
                print("Image Shape:", img.shape)  # Debug: Print image shape

            # Make prediction
            prediction_result = loaded_model.predict(img)  # Assuming loaded_model is defined elsewhere
            print("Prediction Result:", prediction_result)  # Debug: Print prediction result

            # Classify image based on prediction
            if prediction_result > 0.5:
                class_0_images.append(img_name)  # Add image to class 0
            else:
                class_1_images.append(img_name)  # Add image to class 1

        print("Class 0 Images:", class_0_images)  # Debug: Print class 0 images
        print("Class 1 Images:", class_1_images)  # Debug: Print class 1 images

        return render_template('dashboard_2.html', class_0_images=class_0_images, class_1_images=class_1_images)

    return render_template('dashboard_2.html', images=images)




def load_and_preprocess_image(img):
    imag = img.resize((224, 224))  # Resize image if necessary
    img_array = np.array(imag)
    img_array = img_array / 255.0  # Normalize pixel values to [0, 1]
    img_array = np.expand_dims(img_array, axis=0)  # Add batch dimension
    return img_array




if __name__ == '__main__':
    app.run(debug=True)
