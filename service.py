import mysql.connector
import mysql.connector
from flask import Flask, request, jsonify, session
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta, datetime
from flask_wtf import CSRFProtect
import configparser
import os
import re
import bleach

app = Flask(__name__)
config = configparser.ConfigParser()
config.read('config.ini')

# Set up CSRF protection
csrf = CSRFProtect(app)

app.secret_key = os.urandom(24)  # Set a secret key for session encryption
# Set session timeout to 30 minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Set up MySQL connection
db_config = config['database']
app.config['MYSQL_HOST'] = db_config['host']
app.config['MYSQL_PORT'] = int(db_config.get('port'))
app.config['MYSQL_USER'] = db_config['user']
app.config['MYSQL_PASSWORD'] = db_config['password']
app.config['MYSQL_DB'] = db_config['database']

bcrypt = Bcrypt(app)

# Set up rate limiting
app.config['RATE_LIMIT_MESSAGE'] = 'Too many login attempts. Please try again later.'
limiter = Limiter(get_remote_address)
limiter.init_app(app)

# Set the maximum number of failed login attempts before locking the account
MAX_LOGIN_ATTEMPTS = 5

# Set the lockout duration in minutes
LOCKOUT_DURATION = 10


def lockout_account(username):
    # Set the account lockout flag and lockout expiration time in the database
    conn = get_mysql_connection()
    cursor = conn.cursor()

    try:
        lockout_time = datetime.now() + timedelta(minutes=LOCKOUT_DURATION)
        cursor.execute("UPDATE customers SET is_locked = true, lockout_expiration = %s WHERE username = %s",
                       (lockout_time, username))
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def unlock_account(username):
    # Clear the account lockout flag and lockout expiration time in the database
    conn = get_mysql_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("UPDATE customers SET is_locked = false, lockout_expiration = NULL WHERE username = %s",
                       (username,))
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def is_account_locked(username):
    # Check if the account is locked based on the lockout expiration time
    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT is_locked, lockout_expiration FROM customers WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user and user['is_locked'] and user['lockout_expiration'] >= datetime.now():
            return True
        else:
            return False
    finally:
        cursor.close()
        conn.close()


def get_mysql_connection():
    return mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        port=app.config['MYSQL_PORT'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )


def sanitize_input(input_string):
    # Remove HTML tags and sanitize input
    sanitized_input = bleach.clean(input_string, tags=[], attributes={}, protocols=[], strip=True)
    return sanitized_input


def is_strong_password(password):
    # Check if the password meets the minimum length requirement
    if len(password) < 8:
        return False

    # Check if the password contains at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False

    # Check if the password contains at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False

    # Check if the password contains at least one digit
    if not re.search(r'\d', password):
        return False

    # Check if the password contains at least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False

    return True


def regenerate_session():
    # Regenerate session identifier on login or logout to prevent session fixation attacks
    session.clear()
    session.modified = True


@app.route('/message', methods=['GET'])
def message():
    posted_data = request.get_json()
    name = sanitize_input(posted_data['name'])
    return jsonify(" Hope you are having a good time " + name + "!!!")


@app.route('/register', methods=['POST'])
@csrf.exempt  # Exempt CSRF protection for the registration route
def register():
    data = request.get_json()
    username = sanitize_input(data['username'])
    password = sanitize_input(data['password'])

    # Check if the username or password is empty
    if not username or not password:
        return jsonify({'message': 'Registration failed', 'error': 'Username or password cannot be empty'}), 400

    # Check if the password meets the strong password criteria
    if not is_strong_password(password):
        return jsonify({'message': 'Registration failed',
                        'error': 'Password is weak. It must contain at least 8 characters, including uppercase, '
                                 'lowercase, digit, and special characters.'}), 400

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_mysql_connection()
    cursor = conn.cursor()

    try:
        # Check if the username already exists
        cursor.execute("SELECT * FROM customers WHERE username = %s", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            return jsonify({'message': 'Registration failed', 'error': 'Username already exists'}), 400

        # Insert the new user into the database using parameterized query
        insert_query = "INSERT INTO customers (username, password) VALUES (%s, %s)"
        insert_data = (username, hashed_password)
        cursor.execute(insert_query, insert_data)
        conn.commit()

        return jsonify({'message': 'Registration successful'}), 200

    except mysql.connector.Error as error:
        return jsonify({'message': 'Registration failed', 'error': str(error)}), 400

    finally:
        cursor.close()
        conn.close()


@app.route('/login', methods=['POST'])
@csrf.exempt  # Exempt CSRF protection for the registration route
@limiter.limit("5/minute")
@limiter.limit(app.config['RATE_LIMIT_MESSAGE'], error_message=app.config['RATE_LIMIT_MESSAGE'])
def login():
    try:
        data = request.get_json()
        username = sanitize_input(data['username'])
        password = sanitize_input(data['password'])

        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)

        # Check if the account is locked
        if is_account_locked(username):
            return jsonify({'message': 'Login failed', 'error': 'Account is locked. Please try again later.'}), 401

        try:
            # Check if the user exists in the database
            cursor.execute("SELECT * FROM customers WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user:
                # Verify the password using bcrypt
                if bcrypt.check_password_hash(user['password'], password):
                    # Perform additional security checks here if needed (e.g., account locked, two-factor authentication)
                    # ...

                    # Regenerate session identifier
                    regenerate_session()

                    # Set user data in the session
                    session['user_id'] = user['id']
                    session['username'] = user['username']

                    # Authentication successful
                    return jsonify({'message': 'Login successful'})
                else:
                    # Incorrect password
                    # Increment the login attempt count and lock the account if the maximum attempts is reached
                    cursor.execute("UPDATE customers SET login_attempts = login_attempts + 1 WHERE username = %s",
                                   (username,))
                    conn.commit()

                    if user['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                        lockout_account(username)

                    return jsonify({'message': 'Login failed', 'error': 'Invalid username or password'}), 401
            else:
                # User not found
                return jsonify({'message': 'Login failed', 'error': 'Invalid username or password'}), 401
        except mysql.connector.Error as error:
            return jsonify({'message': 'Login failed', 'error': str(error)}), 500
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500


@app.route('/logout', methods=['POST'])
def logout():
    if 'user_id' in session:
        # Clear session data
        session.clear()
        session.modified = True
        return jsonify({'message': 'Logout successful'})
    else:
        return jsonify({'message': 'Logout failed', 'error': 'User not logged in'}), 401


if __name__ == '__main__':
    app.run(debug=True, use_reloader=True, use_debugger=True, ssl_context='adhoc')
