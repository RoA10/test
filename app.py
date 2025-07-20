from flask import Flask, render_template, redirect, url_for, request, session
import base64
import hashlib
import secrets
import psycopg2
import psycopg2.extras
import os

app = Flask(__name__)
app.secret_key = b"opensesame"
db_url = os.environ.get("DATABASE_URL")
HASH_ALGORITHM = "pbkdf2_sha256"

def get_db():
    return psycopg2.connect(db_url, sslmode='require')

def hash_password(password, salt=None, iterations=600000):
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations)
    b64_hash = base64.b64encode(pw_hash).decode().strip()
    return f"{HASH_ALGORITHM}${iterations}${salt}${b64_hash}"

def verify_password(password, password_hash):
    if password_hash.count("$") != 3:
        return False
    algorithm, iterations, salt, _ = password_hash.split("$", 3)
    if algorithm != HASH_ALGORITHM:
        return False
    compare_hash = hash_password(password, salt, int(iterations))
    return secrets.compare_digest(password_hash, compare_hash)

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
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            return render_template("register.html", error_unique=True)

        pw_hash = hash_password(password)
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, pw_hash))
        conn.commit()
    except Exception:
        app.logger.exception("Register failed")
        return render_template("register.html", error=True)
    finally:
        cur.close()
        conn.close()

    return redirect(url_for("login"))

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
    except Exception:
        app.logger.exception("Login DB error")
        user = None
    finally:
        cur.close()
        conn.close()

    if user and verify_password(password, user["password_hash"]):
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("main"))

    return render_template("login.html", error=True)

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
        cur.execute("SELECT * FROM classes WHERE user_id = %s", (session["user_id"],))
        classes = cur.fetchall()
    except Exception:
        app.logger.exception("MAIN ERROR")
        return "Internal Server Error", 500
    finally:
        cur.close()
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
        app.logger.exception("CREATE ERROR")
    finally:
        cur.close()
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
        app.logger.exception("INCREMENT ERROR")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for("main"))

@app.route("/decrement/<int:class_id>", methods=["POST"])
def decrement(class_id):
    if "user_id" not in session:
        return redirect(url_for("login"))
    try:
        conn = get_db()
        cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cur.execute("SELECT count FROM classes WHERE class_id = %s AND user_id = %s",
                    (class_id, session["user_id"]))
        row = cur.fetchone()
        if row and row["count"] > 0:
            cur.execute(
                "UPDATE classes SET count = count - 1 WHERE class_id = %s AND user_id = %s",
                (class_id, session["user_id"])
            )
            conn.commit()
    except Exception:
        app.logger.exception("DECREMENT ERROR")
    finally:
        cur.close()
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
        app.logger.exception("DELETE ALL ERROR")
    finally:
        cur.close()
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
        app.logger.exception("DELETE CLASS ERROR")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for("main"))

if __name__ == "__main__":
    app.run(debug=True)
