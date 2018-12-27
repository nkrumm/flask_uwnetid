from dash import Dash
import dash_html_components as html
from flask import Flask, abort, redirect
from flask_login import (
    LoginManager, login_user, login_required,
    current_user, UserMixin
)
from flask_uwnetid import UWAuthManager

server = Flask(__name__)

server.config.update(
    DEBUG = True,
    SECRET_KEY = 'secret_xxx'
)

# Set up authentication
auth = UWAuthManager(app=server, domain='https://your.domain.com')

# Set up Dash
dash_app = Dash("dash_app_instance", server = server, url_base_pathname='/dashboard/' )

# Protect views
def protect_views(app):
    for view_func in app.server.view_functions:
        if view_func.startswith(app.url_base_pathname):
            app.server.view_functions[view_func] = login_required(app.server.view_functions[view_func])
    return app


@server.route("/")
def home():
    return """
    <a href="/saml/login">Log in</a>
    """

dash_app.layout = html.Div([html.H1('Hello, World.')])

dash_app = protect_views(dash_app)

if __name__ == "__main__":
    server.run()
