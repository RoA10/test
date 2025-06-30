from flask import Flask, render_template, redirect, url_for, request, session
import base64
import hashlib
import secrets
import sqlite3
import psycopg2
import psycopg2.extras

# ハッシュ化アルゴリズム、secret_keyの設定
HASH_ALGORITHM = "pbkdf2_sha256"
app = Flask(__name__)
app.secret_key = b"opensesame"

# ハッシュ化
def hash_password(password, salt=None, iterations=600000):
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    b64_hash = base64.b64encode(pw_hash).decode().strip()
    return f"{HASH_ALGORITHM}${iterations}${salt}${b64_hash}"

# ユーザー認証
def verify_password(password, password_hash):
    if password_hash.count("$") != 3:
        return False
    algorithm, iterations, salt, _ = password_hash.split("$", 3)
    iterations = int(iterations)
    if algorithm != HASH_ALGORITHM:
        return False
    compare_hash = hash_password(password, salt, iterations)
    return secrets.compare_digest(password_hash, compare_hash)

# データベース接続
def get_db():
    conn = psycopg2.connect(
        host="localhost",
        database="todo",
        user="shinmatsumura",
        password="password",  # 実際のパスワードに置き換えてください
        port=5432
    )
    return conn


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

    db = get_db()
    with db:
        if db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone():
            return render_template("register.html", error_unique=True)
        pw_hash = hash_password(password)
        db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, pw_hash))

    return redirect(url_for("login"))

# ログイン画面
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username")
    password = request.form.get("password")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    db.close()

    if user and verify_password(password, user["password_hash"]):
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("main"))
    return render_template("login.html", error=True)

# ログアウト
@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

# 授業一覧
@app.route("/main")
def main():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    classes = db.execute("SELECT * FROM classes WHERE user_id = ?", (session["user_id"],)).fetchall()
    db.close()
    return render_template("main.html", classes=classes)

# 授業追加
@app.route("/create", methods=["GET", "POST"])
def create():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("up.html")

    title = request.form.get("title")
    required = request.form.get("check") == "on"

    if not title.strip():
        return "授業名を入力してください", 400

    db = get_db()
    with db:
        db.execute(
            "INSERT INTO classes (class_title, required, count, user_id) VALUES (?, ?, 1, ?)",
            (title, required, session["user_id"])
        )
    return redirect(url_for("main"))

# 休んだ回数の増加
@app.route("/increment/<int:class_id>", methods=["POST"])
def increment(class_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    with db:
        db.execute("UPDATE classes SET count = count + 1 WHERE class_id = ? AND user_id = ?", (class_id, session["user_id"]))
    return redirect(url_for("main"))

# 休んだ回数の減少
@app.route("/decrement/<int:class_id>", methods=["POST"])
def decrement(class_id):
    if"user_id" not in session:
        return redirect(url_for("login"))
    
    db = get_db()
    with db:
        current = db.execute(
            "SELECT count FROM classes WHERE class_id = ? AND user_id = ?",
            (class_id, session["user_id"])
        ).fetchone()

        if current and current["count"] > 0:
            db.execute(
                "UPDATE classes SET count = count - 1 WHERE class_id = ? AND user_id = ?",
                (class_id, session["user_id"])
            )
    return redirect(url_for("main"))

# 授業の全削除
@app.route("/delete", methods=["POST"])
def delete():
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    with db:
        db.execute("DELETE FROM classes WHERE user_id = ?", (session["user_id"],))
    return redirect(url_for("main"))

# 授業の個別削除
@app.route("/delete/<int:class_id>", methods=["POST"])
def delete_class(class_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    db = get_db()
    with db:
        db.execute("DELETE FROM classes WHERE class_id = ? AND user_id = ?", (class_id, session["user_id"]))
    return redirect(url_for("main"))
