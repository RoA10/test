from flask import Flask, render_template, redirect, url_for, request, session
import hashlib
import secrets
import psycopg2
import psycopg2.extras
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

db_url = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(db_url, sslmode='require', cursor_factory=psycopg2.extras.RealDictCursor)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('main'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])

        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password))
        conn.commit()
        cur.close()
        conn.close()

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        if user and user['password_hash'] == password:
            session['user_id'] = user['id']
            session['username'] = user['username']
            cur.close()
            conn.close()
            return redirect(url_for('main'))
        cur.close()
        conn.close()
        return render_template('login.html', error=True)

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/main')
def main():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM classes WHERE user_id = %s", (session['user_id'],))
        classes = cur.fetchall()
        cur.close()
        conn.close()
        return render_template('main.html', classes=classes)
    except Exception as e:
        app.logger.exception("MAIN ERROR")
        return "Internal Server Error", 500

@app.route('/create', methods=['GET', 'POST'])
def create():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        required = 'check' in request.form

        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO classes (class_title, required, count, user_id) VALUES (%s, %s, 0, %s)",
                (title, required, session['user_id'])
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            app.logger.exception("Create class failed")
            return "Internal Server Error", 500

        return redirect(url_for('main'))

    return render_template('up.html')

@app.route('/increment/<int:class_id>', methods=['POST'])
def increment(class_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "UPDATE classes SET count = count + 1 WHERE class_id = %s AND user_id = %s",
            (class_id, session['user_id'])
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Increment failed")
        return "Internal Server Error", 500

    return redirect(url_for('main'))

@app.route('/decrement/<int:class_id>', methods=['POST'])
def decrement(class_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "SELECT count FROM classes WHERE class_id = %s AND user_id = %s",
            (class_id, session['user_id'])
        )
        current = cur.fetchone()
        if current and current['count'] > 0:
            cur.execute(
                "UPDATE classes SET count = count - 1 WHERE class_id = %s AND user_id = %s",
                (class_id, session['user_id'])
            )
            conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Decrement failed")
        return "Internal Server Error", 500

    return redirect(url_for('main'))

@app.route('/delete/<int:class_id>', methods=['POST'])
def delete_class(class_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM classes WHERE class_id = %s AND user_id = %s",
            (class_id, session['user_id'])
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Delete class failed")
        return "Internal Server Error", 500

    return redirect(url_for('main'))

@app.route('/delete', methods=['POST'])
def delete():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM classes WHERE user_id = %s", (session['user_id'],))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Delete all failed")
        return "Internal Server Error", 500

    return redirect(url_for('main'))
