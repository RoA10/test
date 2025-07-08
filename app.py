# app.py
from flask import Flask, render_template, redirect, url_for, request, session
import base64, hashlib, secrets, os
import psycopg2
import psycopg2.extras
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

def get_db():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL が設定されていません")
    return psycopg2.connect(db_url, sslmode='require')

HASH_ALGO = "pbkdf2_sha256"

def hash_password(password, salt=None, iterations=600000):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    return f"{HASH_ALGO}${iterations}${salt}${base64.b64encode(digest).decode().strip()}"

def verify_password(password, pw_hash):
    parts = pw_hash.split("$")
    if len(parts) != 4 or parts[0] != HASH_ALGO:
        return False
    _, iterations, salt, _ = parts
    return secrets.compare_digest(pw_hash, hash_password(password, salt, int(iterations)))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        c = request.form.get("password_confirmation", "")
        if not u or p != c:
            return render_template("register.html", error=True)

        try:
            with get_db() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                    cur.execute("SELECT 1 FROM users WHERE username=%s", (u,))
                    if cur.fetchone():
                        return render_template("register.html", error_unique=True)
                    cur.execute(
                        "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                        (u, hash_password(p))
                    )
            session.permanent = True
            return redirect(url_for("login"))
        except Exception:
            app.logger.exception("Register failed")
            return render_template("register.html", error=True)

    return render_template("register.html")

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        user = None
        try:
            with get_db() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                    cur.execute("SELECT * FROM users WHERE username=%s", (u,))
                    user = cur.fetchone()
        except Exception:
            app.logger.exception("Login failed")
            return render_template("login.html", error=True)

        if user and verify_password(p, user["password_hash"]):
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("main"))

        return render_template("login.html", error=True)

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
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
    except Exception as e:
        app.logger.exception(f"MAIN failed: {type(e).__name__}: {e}")
        return render_template("error.html", error=e), 500
    finally:
        cur.close()
        conn.close()
    return render_template("main.html", classes=classes)


@app.route("/create", methods=["GET", "POST"])
def create():
    uid = session.get("user_id")
    if not uid:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        required = request.form.get("check") == "on"
        if not title:
            return "授業名を入力してください", 400

        try:
            with get_db() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO classes (class_title, required, count, user_id) VALUES (%s, %s, 1, %s)",
                        (title, required, uid)
                    )
            return redirect(url_for("main"))
        except Exception:
            app.logger.exception("Create failed")
            return "Internal Server Error", 500

    return render_template("up.html")

@app.route("/increment/<int:cid>", methods=["POST"])
def increment(cid):
    uid = session.get("user_id")
    if not uid:
        return redirect(url_for("login"))

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE classes SET count = count + 1 WHERE class_id=%s AND user_id=%s",
                    (cid, uid)
                )
        return redirect(url_for("main"))
    except Exception:
        app.logger.exception("Increment failed")
        return "Internal Server Error", 500

@app.route("/decrement/<int:cid>", methods=["POST"])
def decrement(cid):
    uid = session.get("user_id")
    if not uid:
        return redirect(url_for("login"))

    try:
        with get_db() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(
                    "SELECT count FROM classes WHERE class_id=%s AND user_id=%s",
                    (cid, uid)
                )
                row = cur.fetchone()
                if row and row["count"] > 0:
                    cur.execute(
                        "UPDATE classes SET count = count - 1 WHERE class_id=%s AND user_id=%s",
                        (cid, uid)
                    )
        return redirect(url_for("main"))
    except Exception:
        app.logger.exception("Decrement failed")
        return "Internal Server Error", 500

@app.route("/delete", methods=["POST"])
def delete():
    uid = session.get("user_id")
    if not uid:
        return redirect(url_for("login"))
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM classes WHERE user_id=%s", (uid,))
        return redirect(url_for("main"))
    except Exception:
        app.logger.exception("Delete all failed")
        return "Internal Server Error", 500

@app.route("/delete/<int:cid>", methods=["POST"])
def delete_class(cid):
    uid = session.get("user_id")
    if not uid:
        return redirect(url_for("login"))
    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM classes WHERE class_id=%s AND user_id=%s",
                    (cid, uid)
                )
        return redirect(url_for("main"))
    except Exception:
        app.logger.exception("Delete class failed")
        return "Internal Server Error", 500

if __name__ == "__main__":
    app.run(debug=True)
