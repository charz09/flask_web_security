from flask import Flask, render_template, g, request, redirect, flash, url_for
import sqlite3
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'moha1251'
app.config['DATABASE'] = 'database.db'

# Database initialization
# def get_db():
#     if 'db' not in g:
#         g.db = sqlite3.connect(app.config['DATABASE'])
#         g.db.row_factory = sqlite3.Row
#     return g.db

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

@app.teardown_appcontext
# def close_db(error):
#     db = g.pop('db', None)
#     if db is not None:
#         db.close()


def close_db(error):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if the provided email exists in the database
        # conn = get_db()
        # cursor = conn.cursor()
        # cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        # user = cursor.fetchone()

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?' , (email,)).fetchone()
        db.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            # Successful login, set user as logged in (You may use Flask-Login for this)
            flash('Successfully logged in!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'error')
            
    return render_template('login.html')


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if the email is already registered
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Email is already registered. Please use a different email.')
        else:
            # Hash the password before storing it in the database
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Insert the new user into the database
            cursor.execute("INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)",
                           (first_name, last_name, email, hashed_password))
            conn.commit()

            flash('Registration successful. You can now log in with your credentials.')
            return redirect('/login')

    return render_template('registration.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/security')
def security():
    return render_template('security.html')

@app.route('/quality')
def quality():
    return render_template('quality.html')

@app.route('/usability')
def usability():
    return render_template('usability.html')

if __name__ == '__main__':
    app.run(debug=True)
