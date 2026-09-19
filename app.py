
from flask import Flask, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_NAME = "users.db"


def get_db():
    return sqlite3.connect(DB_NAME)


def create_table():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


@app.route("/")
def home():
    if "username" in session:
        return f"""
        <h2>Welcome, {session['username']}!</h2>
        <p>You are successfully logged in.</p>
        <a href="/logout">Logout</a>
        """
    return """
    <h2>Secure Login System</h2>
    <a href="/register">Register</a><br><br>
    <a href="/login">Login</a>
    """


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 30:
            return "Username must be 3-30 characters."

        if len(password) < 8 or len(password) > 128:
            return "Password must be 8-128 characters."

        hashed_password = generate_password_hash(password)

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )
            conn.commit()
            conn.close()
            return redirect("/login")
        except sqlite3.IntegrityError:
            return "Username already exists."

    return """
    <h2>Register</h2>
    <form method="POST">
        Username: <input name="username" required minlength="3" maxlength="30"><br><br>
        Password: <input type="password" name="password" required minlength="8" maxlength="128"><br><br>
        <button type="submit">Register</button>
    </form>
    <a href="/">Home</a>
    """


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT username, password FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session.clear()
            session["username"] = user[0]
            return redirect("/")

        return "Invalid username or password."

    return """
    <h2>Login</h2>
    <form method="POST">
        Username: <input name="username" required><br><br>
        Password: <input type="password" name="password" required><br><br>
        <button type="submit">Login</button>
    </form>
    <a href="/">Home</a>
    """


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    create_table()
    app.run(host="127.0.0.1", port=5000, debug=False)
