from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import mysql.connector

app = Flask(__name__)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'housing'

bcrypt = Bcrypt(app)


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

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = get_mysql_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO customers (username, password) VALUES (%s, %s)", (username, hashed_password))
        conn.commit()
        return jsonify({'message': 'Registration successful'})
    except mysql.connector.Error as error:
        return jsonify({'message': 'Registration failed', 'error': str(error)}), 400
    finally:
        cursor.close()
        conn.close()


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']

    conn = get_mysql_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM customers WHERE username = %s AND password = %s", (username, password))
    user = cursor.fetchone()

    cursor.close()
    conn.close()

    if user:
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'message': 'Login failed', 'error': 'Invalid username or password'}), 401


if __name__ == '__main__':
    app.run(debug=True)
