from flask import Flask, render_template, redirect, url_for, request, session
import base64
import hashlib
import secrets
import os
import psycopg2
import psycopg2.extras

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

def get_db():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL が設定されていません")
    try:
        conn = psycopg2.connect(db_url, sslmode='require')
        return conn
    except psycopg2.OperationalError as e:
        app.logger.exception("データベース接続エラー")
        raise

HASH_ALGORITHM = "pbkdf2_sha256"

def hash_password(password, salt=None, iterations=600000):
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    b64 = base64.b64encode(pw_hash).decode().strip()
    return f"{HASH_ALGORITHM}${iterations}${salt}${b64}"

def verify_password(password, password_hash):
    parts = password_hash.split("$")
    if len(parts) != 4 or parts[0] != HASH_ALGORITHM:
        return False
    _, iterations, salt, _ = parts
    expected = hash_password(password, salt, int(iterations))
    return secrets.compare_digest(expected, password_hash)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]
        c = request.form["password_confirmation"]
        if not u or p != c:
            return render_template("register.html", error=True)
        try:
            conn = get_db()
            cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            cur.execute("SELECT 1 FROM users WHERE username=%s", (u,))
            if cur.fetchone():
                return render_template("register.html", error_unique=True)
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (u, hash_password(p))
            )
            conn.commit()
        except psycopg2.errors.UniqueViolation:
            app.logger.exception("ユーザー名が既に存在します")
            return render_template("register.html", error_unique=True)
        except Exception:
            app.logger.exception("登録処理中にエラーが発生しました")
            return render_template("register.html", error=True)
        finally:
            if cur:
                cur.close()
            if conn:
                conn.close()
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    u = request.form["username"]
    p = request.form["password"]
    user = None
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM users WHERE username=%s", (u,))
        user = cur.fetchone()
    except Exception:
        app.logger.exception("ログイン処理中にエラーが発生しました")
        return render_template("login.html", error=True)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    if user and verify_password(p, user["password_hash"]):
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("main"))
    return render_template("login.html", error=True)

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))

@app.route("/main")
def main():
    if "user_id" not in session:
        return redirect(url_for("login"))
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM classes WHERE user_id=%s", (session["user_id"],))
        classes = cur.fetchall()
    except Exception:
        app.logger.exception("授業一覧取得中にエラーが発生しました")
        return "Internal Server Error", 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return render_template("main.html", classes=classes)

@app.route("/create", methods=["GET", "POST"])
def create():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("up.html")
    title = request.form.get("title", "").strip()
    required = request.form.get("check") == "on"
    if not title:
        return "授業名を入力してください", 400
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO classes (class_title, required, count, user_id) VALUES (%s, %s, 1, %s)",
            (title, required, session["user_id"])
        )
        conn.commit()
    except Exception:
        app.logger.exception("授業追加処理中にエラーが発生しました")
        return "Internal Server Error", 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return redirect(url_for("main"))

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
    except Exception:
        app.logger.exception("出席回数増加処理中にエラーが発生しました")
        return "Internal Server Error", 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return redirect(url_for("main"))

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
        row = cur.fetchone()
        if row and row["count"] > 0:
            cur.execute(
                "UPDATE classes SET count = count - 1 WHERE class_id = %s AND user_id = %s",
                (class_id, session["user_id"])
            )
            conn.commit()
    except Exception:
        app.logger.exception("出席回数減少処理中にエラーが発生しました")
        return "Internal Server Error", 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return redirect(url_for("main"))

@app.route("/delete", methods=["POST"])
def delete():
    if "user_id" not in session:
        return redirect(url_for("login"))
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM classes WHERE user_id = %s", (session["user_id"],))
        conn.commit()
    except Exception:
        app.logger.exception("授業削除処理中にエラーが発生しました")
        return "Internal Server Error", 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return redirect(url_for("main"))

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
    except Exception:
        app.logger.exception("個別授業削除処理中にエラーが発生しました")
        return "Internal Server Error", 500
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()
    return redirect(url_for("main"))

if __name__ == "__main__":
    app.run(debug=True)
