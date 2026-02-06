#!/usr/bin/env python3
"""
app_http_fixed.py
Versione corretta del tuo server Flask:
- salva utenti in un semplice DB persistente (shelve)
- usa password hash (werkzeug.security)
- mostra "Welcome, <nome>! You are now logged in" dopo la registrazione/login
- mantiene il meccanismo CSRF per testing locale HTTP
"""

import os
from flask import (
    Flask,
    request,
    render_template_string,
    session,
    make_response,
    redirect,
    url_for,
)
from secrets import token_hex
from werkzeug.security import generate_password_hash, check_password_hash
import shelve

# Toggle debug prints for CSRF troubleshooting in a local lab
DEBUG_CSRF = False

app = Flask("Kinda Secure Pizzeria Siciliana - HTTP")

# Secret key for session (in production, keep this out of source code)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_secret_key_in_production")

# For local HTTP testing we do not force SESSION_COOKIE_SECURE
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

# Simple persistent user store using shelve
DB_PATH = os.path.join(os.path.dirname(__file__), "users_db")

# ------------------------------
# TEMPLATE PRINCIPALE
# ------------------------------
page = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Kinda Secure Pizzeria Siciliana</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body { margin:0; padding:0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg,#faf7f2 0%,#f0ebe4 100%); color:#333; }
      header { background: linear-gradient(90deg,#b22222,#d63b3b); color:white; padding:22px; text-align:center; font-size:32px; font-weight:bold; position:relative; }
      .nav-buttons { position:absolute; right:20px; top:50%; transform:translateY(-50%); }
      .nav-buttons a { color:white; text-decoration:none; font-weight:bold; margin-left:12px; padding:8px 12px; border-radius:6px; background:rgba(255,255,255,0.12); }
      .hero { position:relative; height:360px; overflow:hidden; border-bottom:4px solid #b22222; }
      .hero img { width:100%; height:100%; object-fit:cover; filter:brightness(0.55); }
      .hero-text { position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); color:white; text-shadow:0 3px 10px rgba(0,0,0,0.7); font-size:44px; font-weight:bold; text-align:center; }
      .section { max-width:1000px; margin:60px auto; padding:20px; }
      .section h2 { font-size:30px; margin-bottom:20px; color:#b22222; text-align:center; }
      .menu-items { display:flex; gap:25px; flex-wrap:wrap; justify-content:center; }
      .menu-item { background:white; padding:20px; border-radius:14px; width:260px; box-shadow:0 4px 18px rgba(0,0,0,0.12); transition:transform .2s ease; }
      .menu-item:hover { transform:translateY(-4px); box-shadow:0 6px 22px rgba(0,0,0,0.18); }
      .menu-item img { width:100%; border-radius:12px; height:180px; object-fit:cover; margin-bottom:12px; }
      .menu-item h3 { margin-top:8px; font-size:20px; text-align:center; color:#333; }
      .subscribe-box { max-width:450px; margin:90px auto; background:white; padding:40px; border-radius:14px; box-shadow:0 6px 25px rgba(0,0,0,0.15); text-align:center; }
      label { font-weight:bold; display:block; margin-top:18px; color:#444; text-align:left; }
      input[type="text"], input[type="password"] { width:100%; padding:12px; margin-top:6px; border:1px solid #ccc; border-radius:8px; font-size:15px; transition:border-color .2s ease, box-shadow .2s ease; }
      input:focus { border-color:#b22222; outline:none; box-shadow:0 0 0 2px rgba(178,34,34,0.12); }
      button { width:100%; padding:15px; margin-top:30px; background:linear-gradient(90deg,#b22222,#d63b3b); color:white; border:none; border-radius:8px; font-size:18px; cursor:pointer; }
      .success { text-align:center; margin-top:20px; color:#2e7d32; font-weight:bold; font-size:18px; }
      .logout-link { margin-top:18px; display:inline-block; color:#b22222; font-weight:bold; text-decoration:none; }
      .error { text-align:center; margin-top:12px; color:#b22222; font-weight:bold; }
      footer { text-align:center; padding:25px; margin-top:60px; background:#eee; color:#555; font-size:14px; }
    </style>
  </head>
  <body>
    <header>
      Kinda Secure Pizzeria Siciliana
      <div class="nav-buttons">
        {% if logged_in %}
          <a href="{{ url_for('logout') }}">Logout</a>
        {% else %}
          <a href="{{ url_for('login') }}">Login</a>
        {% endif %}
      </div>
    </header>

    <div class="hero">
      <img src="https://images.unsplash.com/photo-1601924582975-7e1e0a1a3e3b" alt="Pizza hero image">
      <div class="hero-text">Authentic Sicilian Pizza, Made With Love</div>
    </div>

    <div class="section">
      <h2>Our Menu</h2>
      <div class="menu-items">
        <div class="menu-item">
          <img src="https://images.unsplash.com/photo-1601924582975-7e1e0a1a3e3b" alt="Margherita pizza">
          <h3>Margherita</h3>
        </div>
        <div class="menu-item">
          <img src="https://images.unsplash.com/photo-1548365328-9f547b1c1d9d" alt="Diavola pizza">
          <h3>Diavola</h3>
        </div>
        <div class="menu-item">
          <img src="https://images.unsplash.com/photo-1601924582975-7e1e0a1a3e3b?ixlib=rb-4.0.3" alt="Capricciosa pizza">
          <h3>Capricciosa</h3>
        </div>
        <div class="menu-item">
          <img src="https://images.unsplash.com/photo-1603079842519-3e8d3d8e9e6d" alt="Quattro formaggi pizza">
          <h3>Quattro Formaggi</h3>
        </div>
      </div>
    </div>

    <div class="subscribe-box">
      {% if logged_in %}
        <h3>Welcome, {{ username }}!</h3>
        <div class="success">You are now logged in.</div>
        <a class="logout-link" href="{{ url_for('logout') }}">Logout</a>
      {% else %}
        <h3>Subscribe</h3>
        <div class="subtitle">Subscribe to get a 10% discount</div>
        <form method="POST" action="{{ url_for('index') }}">
          <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
          <label for="username">Username</label>
          <input type="text" id="username" name="username" required>
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required>
          <button type="submit">Subscribe</button>
        </form>
        {% if success %}
          <div class="success">Subscription received.</div>
        {% endif %}
        {% if error %}
          <div class="error">{{ error }}</div>
        {% endif %}
      {% endif %}
    </div>

    <footer>© 2026 Kinda Secure Pizzeria Siciliana — All rights reserved</footer>
  </body>
</html>
"""

# ------------------------------
# TEMPLATE LOGIN
# ------------------------------
login_page = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Login — Pizzeria Siciliana</title>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <style>
      body { background:#faf7f2; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin:0; }
      .box { max-width:420px; margin:100px auto; background:white; padding:32px; border-radius:12px; box-shadow:0 6px 25px rgba(0,0,0,0.12); text-align:center; }
      h2 { color:#b22222; margin:0 0 12px 0; }
      input { width:100%; padding:12px; margin-top:10px; border:1px solid #ccc; border-radius:8px; }
      button { width:100%; padding:12px; margin-top:18px; background:linear-gradient(90deg,#b22222,#d63b3b); color:white; border:none; border-radius:8px; cursor:pointer; }
      a { display:inline-block; margin-top:12px; color:#b22222; text-decoration:none; }
      .error { color:#b22222; margin-top:12px; font-weight:bold; }
    </style>
  </head>
  <body>
    <div class="box">
      <h2>Login</h2>
      <form method="POST" action="{{ url_for('login') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Log in</button>
      </form>
      {% if error %}
        <div class="error">{{ error }}</div>
      {% endif %}
      <a href="{{ url_for('index') }}">Back to home</a>
    </div>
  </body>
</html>
"""

# ------------------------------
# HELPERS
# ------------------------------
def add_security_headers(response):
    # Keep safe headers but DO NOT set HSTS for HTTP dev
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


def ensure_csrf_token():
    """
    Ensure a CSRF token exists in session and return it.
    """
    token = session.get("csrf_token")
    if not token:
        token = token_hex(16)
        session["csrf_token"] = token
    return token


def user_store_get(username):
    """Return stored user dict or None"""
    with shelve.open(DB_PATH) as db:
        return db.get(username)


def user_store_save(username, password_hash):
    """Save user with hashed password"""
    with shelve.open(DB_PATH, writeback=True) as db:
        db[username] = {"password_hash": password_hash}


# ------------------------------
# ROUTES
# ------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    success = False
    error = None

    # Ensure session token exists
    token = ensure_csrf_token()

    # If cookie not present, set it so browser will send it back on POST
    cookie_token = request.cookies.get("csrf_token")
    resp = None
    if not cookie_token:
        # set cookie with same token as session
        resp = make_response()  # we'll fill body later
        resp.set_cookie(
            "csrf_token",
            token,
            httponly=False,
            samesite="Lax",
            secure=False,
        )
        if DEBUG_CSRF:
            print("Set cookie csrf_token:", token)

    if request.method == "POST":
        # Read form token and compare to cookie token and session token
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        session_token = session.get("csrf_token", "")

        if DEBUG_CSRF:
            print("FORM token:", form_token)
            print("COOKIE token:", cookie_token)
            print("SESSION token:", session_token)

        # Accept if form matches cookie OR matches session (compat)
        if not form_token or (form_token != cookie_token and form_token != session_token):
            resp_err = make_response("Invalid CSRF token", 400)
            return add_security_headers(resp_err)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "Username and password are required."
        else:
            # If username already exists, treat as registration conflict
            existing = user_store_get(username)
            if existing:
                error = "Username already registered. Please log in instead."
            else:
                # Save user (store hashed password)
                pw_hash = generate_password_hash(password)
                user_store_save(username, pw_hash)

                # Log the user in
                session["logged_in"] = True
                session["username"] = username
                success = True
                # After successful registration, redirect to GET so template shows logged_in state
                return redirect(url_for("index"))

    # Render page with csrf_token from session (keeps template simple)
    html = render_template_string(
        page,
        csrf_token=session.get("csrf_token"),
        success=success,
        logged_in=session.get("logged_in", False),
        username=session.get("username", ""),
        error=error,
    )

    if resp is None:
        resp = make_response(html)
    else:
        resp.set_data(html)

    return add_security_headers(resp)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Ensure token exists and cookie is set
    token = ensure_csrf_token()
    cookie_token = request.cookies.get("csrf_token")
    resp = None
    if not cookie_token:
        resp = make_response()
        resp.set_cookie("csrf_token", token, httponly=False, samesite="Lax", secure=False)
        if DEBUG_CSRF:
            print("Set cookie csrf_token (login):", token)

    error = None

    if request.method == "POST":
        form_token = request.form.get("csrf_token", "")
        cookie_token = request.cookies.get("csrf_token", "")
        session_token = session.get("csrf_token", "")

        if DEBUG_CSRF:
            print("FORM token (login):", form_token)
            print("COOKIE token (login):", cookie_token)
            print("SESSION token (login):", session_token)

        if not form_token or (form_token != cookie_token and form_token != session_token):
            resp_err = make_response("Invalid CSRF token", 400)
            return add_security_headers(resp_err)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            error = "Username and password are required."
        else:
            stored = user_store_get(username)
            if not stored:
                error = "No such user. Please subscribe first."
            else:
                if check_password_hash(stored["password_hash"], password):
                    session["logged_in"] = True
                    session["username"] = username
                    return redirect(url_for("index"))
                else:
                    error = "Invalid credentials."

    html = render_template_string(login_page, csrf_token=session.get("csrf_token"), error=error)
    if resp is None:
        resp = make_response(html)
    else:
        resp.set_data(html)
    return add_security_headers(resp)


@app.route("/logout")
def logout():
    session.clear()
    # Clear cookie too
    resp = redirect(url_for("index"))
    resp.set_cookie("csrf_token", "", expires=0)
    return add_security_headers(resp)


# ------------------------------
# MAIN
# ------------------------------
if __name__ == "__main__":
    # Run on localhost for local testing
    # IMPORTANT: use the same host/port in the browser (e.g., 192.168.75.99:5000)
    app.run(host="192.168.10.99", port=5000, debug=True)
