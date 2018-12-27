import os
from flask import Flask, abort
from flask_login import login_required
from flask_uwnetid import UWAuthManager

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

auth = UWAuthManager(
	app=app,
	domain='https://your.domain.com',
	x509cert=os.environ.get("X509CERT", default=None),
	private_key=os.environ.get("PRIVATEKEY", default=None))

@app.route('/')
@login_required
def home():
    return "Hello"


if __name__ == "__main__":
    app.run()