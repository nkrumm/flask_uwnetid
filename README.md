# flask_uwnetid: UW NetID SAML authentication

**NOTE**: This library is 
[*mirrored* to github here](https://github.com/nkrumm/flask_uwnetid). If you need to `pip install` this package outside of the UW VPN, you can use that repository.

This package provides one-line integration of the UWNetID SAML Identity Provider (i.e., "Shibboleth"). 

**Please note:** This package is intended for use with the UWNetID service only; use with other IdPs is not supported.

## Installation

Installation follows a typical `python setup.py install` pattern. 

## Example use:

This example can be found in `examples/basic_app.py`. 

**You must set the domain name** to the domain of your application. If supported on your network, you may be able to use `localtunnel` for local development (see below).

Your application must be registered with the UW IdP as a service provider.

```python
from flask import Flask, abort
from flask_login import login_required
from flask_uwnetid import UWAuthManager

app = Flask(__name__)
app.secret_key = "YOURSECRETKEY"

auth = UWAuthManager(app=app, domain='https://your.domain.com')

@app.route('/')
@login_required
def home():
    return "Hello"


if __name__ == "__main__":
    app.run()
```


### Generating a secret key:

Run the following on your terminal and copy/paste it into your app. 
For security reasons, it is recommended that you _do not_ commit this key or save it to a filesystem, but rather set it via environment variables.

    python -c 'import os; print(os.urandom(16))'


### Using localtunnel:
For local testing purposes, you can proxy traffic via https://localtunnel.me/. To install and begin tunneling:
```
npm install -g localtunnel
lt -p 5000 -s your_desired_hostname
```
This will set up https://your_desired_hostname.localtunnel.me, and will forward all web traffic to http://localhost:5000.


### Using Heroku or Dokku:

From the `python3-saml` [docs](https://github.com/onelogin/python3-saml/#getting-up-and-running-on-heroku):

*Getting python3-saml up and running on Heroku will require some extra legwork: python3-saml depends on python-xmlsec which depends on headers from the xmlsec1-dev linux package to install correctly.*

As Dokku uses Heroku/Herokuish buildpacks, we need to tell Dokku to use a modified set of buildpacks. While typically just a single buildpack is specified (or automatically inferred from the pushed package), they can also be specified in a `.buildpacks` file. This file should contain:

    https://github.com/ABASystems/heroku-buildpack-apt
    https://github.com/heroku/heroku-buildpack-python

The first buildpack allows for arbitrary Apt installation during deployment. The buildpack expects an `Aptfile`, which contains the package we want to install:

    libxmlsec1-dev

Finally we need a `Procfile`:

    web: gunicorn app_flask_login:app

(Note that `gunicorn` needs to be added to the `requirements.txt` file with this setup as well.)
