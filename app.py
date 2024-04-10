
import os
import pathlib

import requests
import json
import sqlite3
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.oauth2 import id_token




app = Flask(__name__)



app.secret_key = "gds_4569_sdjdsjhss_884iewweowie"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


GOOGLE_CLIENT_ID = "368560386506-vb4dpt92fe025bskrsgjhd6hjsfukck0.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")



flow = Flow.from_client_secrets_file(
     client_secrets_file = client_secrets_file,
     scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
     redirect_uri ="http://127.0.0.1:5000/callback")


def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" not in session:
            return abort(401) #autorizan req
        else:
            return function()
   
    return wrapper           

@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/")
def home():
     return render_template("index.html")

@app.route("/tournament")

def tournament():
     return render_template("tournament.html")

@app.route("/contact")
def contact():
     return render_template("contact.html")

@app.route("/reviews")
def reviews():
     return render_template("review.html")

@app.route("/blog")
def blog():
     return render_template("blog.html")

@app.route("/pubg")
def pubg():
     return render_template("pubg.html")     


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
         abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session) 
    token_request = google.auth.transport.requests.Request(session = cached_session)

    id_info  = id_token.verify_oauth2_token(

        id_token = credentials._id_token,
        request  = token_request,
        audience = GOOGLE_CLIENT_ID

    )   
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect("/protected_area")

@app.route("/logout")

def logout():
    session.clear()
    return redirect("/")


@app.route("/protected_area")
@login_is_required
def protected_area():
    return  f"hello, {session['name']} <br/>   <a href ='/logout'><button>Logout</button></a>"



@app.route("/register")
def register():
    pass 

if __name__ == "__main__":
     app.run(debug=True)