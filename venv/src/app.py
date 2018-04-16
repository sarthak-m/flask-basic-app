from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
from data import Tweets
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
import pymysql.cursors

app = Flask(__name__)

connection = pymysql.connect(host='localhost',
                             user='root',
                             password='NpQB5lZHrOD1jQk8',
                             db='flask',
                             cursorclass=pymysql.cursors.DictCursor)

Tweets = Tweets()


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/tweets', methods=['GET'])
def tweets():
    return render_template('tweets.html', tweets=Tweets)


@app.route('/tweets/<string:id>', methods=['GET', 'POST'])
def tweet(id):
    return render_template('tweet.html', id=id)


# Register Form class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)

    if request.method == "POST" and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)",
                           (name, email, username, password))

            # Commit to DB
            connection.commit()

            # Close connection
            cursor.close()
            connection.close()

            flash('You are now registered and can log in', 'success')

            return redirect(url_for('login'))
    return render_template('register.html', form=form)


# Check if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))

    return wrap


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        with connection.cursor() as cursor:

            result = cursor.execute("SELECT * FROM USERS WHERE USERNAME = %s", [username])
            # app.logger.info(result)
            # return redirect(url_for('login'))

            if result > 0:
                data = cursor.fetchone()
                password = data['password']
    
                if sha256_crypt.verify(password_candidate, password):
                    session['logged_in'] = True
                    session['username'] = username

                    flash('You are now logged in', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    error = 'Password mismatch'
                    return render_template('login.html', error=error)

            else:
                error = 'Username not found'
                return render_template('login.html', error=error)

    else:
        return render_template('login.html')


# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')


# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out', 'session')
    return redirect(url_for('login'))


# Dashboard
@app.route('/compose_tweet')
@is_logged_in
def dashboard():
    return render_template('compose_tweet.html')


if __name__ == "__main__":
    app.secret_key = 'secret123'
    app.run(debug=True)
