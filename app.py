from flask import Flask, render_template, redirect, url_for, request, session
import base64
import hashlib
import secrets
import psycopg2
import psycopg2.extras
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
db_url = os.environ.get("DATABASE_URL")

# パスワード検証関数
def verify_password(password, stored_hash):
    hashed_input = base64.b64encode(hashlib.sha256(password.encode()).digest()).decode()
    return hashed_input == stored_hash

# DB接続
def get_db():
    return psycopg2.connect(db_url, sslmode='require', cursor_factory=psycopg2.extras.RealDictCursor)

# トップページ → ログイン画面
@app.route('/')
def index():
    return render_template('login.html')

# ログイン処理
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        if user and verify_password(password, user["password_hash"]):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('main'))
        else:
            return render_template('login.html', error='ログインに失敗しました')
    except Exception as e:
        app.logger.error(f"LOGIN ERROR: {e}")
        return render_template('login.html', error='内部エラーが発生しました')
    finally:
        if conn:
            conn.close()

# ログアウト
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# 授業一覧表示
@app.route('/main')
def main():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM classes WHERE user_id = %s ORDER BY class_id", (session['user_id'],))
        classes = cur.fetchall()
        return render_template('main.html', classes=classes)
    except Exception as e:
        app.logger.error(f"MAIN ERROR: {e}")
        return "Internal Server Error", 500
    finally:
        if conn:
            conn.close()

# 授業追加ページ表示
@app.route('/create')
def create():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    return render_template('create.html')

# 授業追加処理
@app.route('/create', methods=['POST'])
def create_post():
    class_title = request.form['class_title']
    required = 'required' in request.form
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO classes (class_title, required, count, user_id)
            VALUES (%s, %s, 0, %s)
        """, (class_title, required, session['user_id']))
        conn.commit()
        return redirect(url_for('main'))
    except Exception as e:
        app.logger.error(f"CREATE ERROR: {e}")
        return "Internal Server Error", 500
    finally:
        if conn:
            conn.close()

# 回数を増やす
@app.route('/increment/<int:class_id>', methods=['POST'])
def increment(class_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE classes SET count = count + 1 WHERE class_id = %s AND user_id = %s",
                    (class_id, session['user_id']))
        conn.commit()
        return redirect(url_for('main'))
    except Exception as e:
        app.logger.error(f"INCREMENT ERROR: {e}")
        return "Internal Server Error", 500
    finally:
        if conn:
            conn.close()

# 回数を減らす
@app.route('/decrement/<int:class_id>', methods=['POST'])
def decrement(class_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE classes SET count = GREATEST(count - 1, 0) WHERE class_id = %s AND user_id = %s",
                    (class_id, session['user_id']))
        conn.commit()
        return redirect(url_for('main'))
    except Exception as e:
        app.logger.error(f"DECREMENT ERROR: {e}")
        return "Internal Server Error", 500
    finally:
        if conn:
            conn.close()

# 授業削除
@app.route('/delete_class/<int:class_id>', methods=['POST'])
def delete_class(class_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM classes WHERE class_id = %s AND user_id = %s", (class_id, session['user_id']))
        conn.commit()
        return redirect(url_for('main'))
    except Exception as e:
        app.logger.error(f"DELETE ERROR: {e}")
        return "Internal Server Error", 500
    finally:
        if conn:
            conn.close()

# すべて削除
@app.route('/delete', methods=['POST'])
def delete():
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM classes WHERE user_id = %s", (session['user_id'],))
        conn.commit()
        return redirect(url_for('main'))
    except Exception as e:
        app.logger.error(f"DELETE ALL ERROR: {e}")
        return "Internal Server Error", 500
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    app.run(debug=True)
