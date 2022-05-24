'''
Install dependencies
pip3(or pip) install flask flask_sqlalchemy flask_login flask_bcrypt flask_wtf wtforms email_validator
'''

from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
# Bcrypt for hashing/encrypting our passwords
from flask_bcrypt import Bcrypt

# Creating an instance app from Flask
app = Flask(__name__)
# Create an instance of the databse for the app
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# Configures & connect our database file with our databse.db file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Secret key is used to secure the session cookie
# Should be kept strong if this is a production environment
app.config['SECRET_KEY'] = 'secretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Creating a table in SQLite database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True) # Integer Value & treated as a primary key
    username = db.Column(db.String(20), nullable=False, unique=True) # UNIQUE String of length 20 & cannot be empty!
    password = db.Column(db.String(80), nullable=False) # String of length 80 & cannot be empty!

'''
Add this User in your database by opening terminal and follow the commands:
python3(or python)
>>> from app import db
>>> db.create_all()
It will create the User table in our database.
>>> exit()
'''

'''
To see that changes have been reflected or not:
Open terminal:
sqlite3 database.db # first install sqlite3 if not installed
>>> .tables
>>> .exit
'''

# Creating a Registration Form Class
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"Placeholder" : "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder" : "Password"})
    submit = SubmitField("Register")

    # Validates a username if it exists in database or not!
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()

        if existing_user_username:
            raise ValidationError("That Username already exists! Please choose a different one.")

# Creating a Login Form Class
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"Placeholder" : "Username"})
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder" : "Password"})
    submit = SubmitField("Login")

# Home Route will be accessible only when a user is logged in!
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
# @login_manager.user_loader
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    # Whenever we submit the form, it will create the hashed version of this password and create a new User that will be be stored in our database. 
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    """
    sqlite command to see if the user exist in database:
    Open terminal,
    sqlite3 database.db
    >>> select * from user;
    """

    return render_template('register.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)