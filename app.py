from flask import Flask, render_template, redirect, url_for, request, session
import base64
import hashlib
import secrets
import psycopg2
import psycopg2.extras
import os

app = Flask(__name__)
db_url = os.environ.get("DATABASE_URL")

def get_db():
    conn = psycopg2.connect(db_url, sslmode='require')
    return conn

# ハッシュ化アルゴリズム、secret_keyの設定
HASH_ALGORITHM = "pbkdf2_sha256"
app.secret_key = b"opensesame"

# ハッシュ化関数
def hash_password(password, salt=None, iterations=600000):
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    b64_hash = base64.b64encode(pw_hash).decode().strip()
    return f"{HASH_ALGORITHM}${iterations}${salt}${b64_hash}"

# パスワード検証関数
def verify_password(password, password_hash):
    if password_hash.count("$") != 3:
        return False
    algorithm, iterations, salt, _ = password_hash.split("$", 3)
    iterations = int(iterations)
    if algorithm != HASH_ALGORITHM:
        return False
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)

# 新規登録
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form.get("username")
    password = request.form.get("password")
    confirm = request.form.get("password_confirmation")

    if not username or not password or password != confirm:
        return render_template("register.html", error=True)

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return render_template("register.html", error_unique=True)

        pw_hash = hash_password(password)
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, pw_hash))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Register failed")
        return render_template("register.html", error=True)

    return redirect(url_for("login"))

# ログイン
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and verify_password(password, user["password_hash"]):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("main"))
        else:
            return render_template("login.html", error=True)
    except Exception as e:
        app.logger.exception("Password verification failed")
        return render_template("login.html", error=True)

# ログアウト
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    session.pop("username", None)
    return redirect(url_for("login"))

# 授業一覧
@app.route("/main")
def main():
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM classes WHERE user_id = %s", (session["user_id"],))
        classes = cur.fetchall()
        cur.close()
        conn.close()
        return render_template("main.html", classes=classes)
    except Exception as e:
        app.logger.exception("MAIN ERROR")
        return "Internal Server Error", 500

# 授業追加
@app.route("/create", methods=["GET", "POST"])
def create():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("up.html")

    title = request.form.get("title")
    required = request.form.get("check") == "on"

    if not title or not title.strip():
        return "授業名を入力してください", 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO classes (class_title, required, count, user_id) VALUES (%s, %s, 1, %s)",
            (title, required, session["user_id"])
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Create class failed")
        return "Internal Server Error", 500

    return redirect(url_for("main"))

# 休んだ回数の増加
@app.route("/increment/<int:class_id>", methods=["POST"])
def increment(class_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "UPDATE classes SET count = count + 1 WHERE class_id = %s AND user_id = %s",
            (class_id, session["user_id"])
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Increment failed")
        return "Internal Server Error", 500

    return redirect(url_for("main"))

# 休んだ回数の減少
@app.route("/decrement/<int:class_id>", methods=["POST"])
def decrement(class_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute(
            "SELECT count FROM classes WHERE class_id = %s AND user_id = %s",
            (class_id, session["user_id"])
        )
        current = cur.fetchone()
        if current and current["count"] > 0:
            cur.execute(
                "UPDATE classes SET count = count - 1 WHERE class_id = %s AND user_id = %s",
                (class_id, session["user_id"])
            )
            conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Decrement failed")
        return "Internal Server Error", 500

    return redirect(url_for("main"))

# 授業の全削除
@app.route("/delete", methods=["POST"])
def delete():
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM classes WHERE user_id = %s", (session["user_id"],))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Delete all failed")
        return "Internal Server Error", 500

    return redirect(url_for("main"))

# 授業の個別削除
@app.route("/delete/<int:class_id>", methods=["POST"])
def delete_class(class_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM classes WHERE class_id = %s AND user_id = %s",
            (class_id, session["user_id"])
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        app.logger.exception("Delete class failed")
        return "Internal Server Error", 500

    return redirect(url_for("main"))

print("入力されたパスワード:", password)
print("DBにあるハッシュ:", user["password_hash"])
print("検証結果:", verify_password(password, user["password_hash"]))
