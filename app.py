import traceback
import logging

# Flaskアプリ初期化のあとに
app.logger.setLevel(logging.DEBUG)

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
        app.logger.error("MAIN ERROR\n" + traceback.format_exc())
        return "Internal Server Error", 500
