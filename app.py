from flask import Flask, render_template, redirect, url_for, request, session
import base64, hashlib, secrets, psycopg2, psycopg2.extras, os

app = Flask(__name__)
app.secret_key = b"opensesame"
db_url = os.environ.get("DATABASE_URL")
HASH_ALGORITHM = "pbkdf2_sha256"

def get_db():
    return psycopg2.connect(db_url, sslmode='require')

def hash_password(...):  # 省略
def verify_password(...):  # 省略

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
    except Exception as e:
        app.logger.exception("DB error on login")
        return render_template("login.html", error=True)
    finally:
        cur.close()
        conn.close()

    if user and verify_password(password, user["password_hash"]):
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("main"))
    return render_template("login.html", error=True)

# …register, main, create, etc.も同様に例外処理を追加…

if __name__ == "__main__":
    app.run(debug=True)
