import configparser

import mysql.connector
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
config = configparser.ConfigParser()
config.read('config.ini')

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


def get_mysql_connection():
    return mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        port=app.config['MYSQL_PORT'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )


@app.route("/message", methods=["GET"])
def message():
    posted_data = request.get_json()
    name = posted_data['name']
    return jsonify(" Hope you are having a good time " + name + "!!!")


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']

    # Check if the username or password is empty
    if not username or not password:
        return jsonify({'message': 'Registration failed', 'error': 'Username or password cannot be empty'}), 400

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

        # Insert the new user into the database
        cursor.execute("INSERT INTO customers (username, password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()

        return jsonify({'message': 'Registration successful'}), 200

    except mysql.connector.Error as error:
        return jsonify({'message': 'Registration failed', 'error': str(error)}), 400

    finally:
        cursor.close()
        conn.close()


@app.route('/login', methods=['POST'])
@limiter.limit("5/minute")
@limiter.limit(app.config['RATE_LIMIT_MESSAGE'], error_message=app.config['RATE_LIMIT_MESSAGE'])
def login():
    try:
        data = request.get_json()
        username = data['username']
        password = data['password']

        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            # Check if the user exists in the database
            cursor.execute("SELECT * FROM customers WHERE username = %s", (username,))
            user = cursor.fetchone()

            if user:
                # Verify the password using bcrypt
                if bcrypt.check_password_hash(user['password'], password):
                    # Perform additional security checks here if needed (e.g., account locked, two-factor authentication)
                    # ...

                    # Authentication successful
                    return jsonify({'message': 'Login successful'})
                else:
                    # Incorrect password
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


if __name__ == '__main__':
    app.run(debug=True)
