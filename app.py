import os
import msal
import sqlite3
from user import User
from flask import Flask, request, redirect, url_for
from db import init_db_command
from flask_login import LoginManager, current_user, login_user, login_required, logout_user

AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", None)
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", None)
AUTHORITY_URL = 'https://login.microsoftonline.com/7b92c877-5b08-4dde-b025-ae827f46bfed'
SCOPES=["User.Read", "email"]

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)

try:
    init_db_command()
except sqlite3.OperationalError:
    # Assume it's already been created
    pass

client_ins = msal.ConfidentialClientApplication(
    client_id=AZURE_CLIENT_ID,
    client_credential=AZURE_CLIENT_SECRET,
    authority=AUTHORITY_URL
)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route("/")
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Azure Profile Picture:</p>"
            '<img src="{}" alt="Azure profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login">Azure Login</a>'

@app.route("/about")
def about():
    if current_user.is_authenticated:
        print(current_user.name, current_user.email, current_user.profile_pic)
        return "about"
    else:
        print('else')
        return redirect(url_for('login'))

@app.route("/login")
def login():
    authz_request_url = client_ins.get_authorization_request_url(SCOPES, 
            redirect_uri=request.base_url+"/callback")
    return redirect(authz_request_url)

@app.route("/login/callback")
def callback():
    auth_code = request.args.get("code")
    access_token = client_ins.acquire_token_by_authorization_code(code=auth_code,
                        scopes=SCOPES, redirect_uri=request.base_url)
    
    claims = access_token["id_token_claims"]
    user = User(
        id_=claims["sub"], name=claims["name"], email=claims["email"], profile_pic=""
    )

    if not User.get(claims["sub"]):
        User.create(claims["sub"], claims["name"], claims["email"], "")

    login_user(user)
    return redirect(url_for("index"))

@app.route("/logout")
@login_required
def logout():
    logout_user()

    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(ssl_context="adhoc", debug=True, port=5001)
