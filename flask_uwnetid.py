from flask import redirect, abort, request, current_app, make_response, session
from flask_login import (
    LoginManager, login_user, login_required,
    current_user, UserMixin
)
from flask.views import View
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from urllib.parse import urlparse

import json

class SecurityException(Exception):
    pass

class User(UserMixin):
    def __init__(self, id):
        self.id = id

UW_METADATA_ENDPOINT = 'https://idp.u.washington.edu/metadata/idp-metadata.xml'

class UWAuthManager(object):

    def __init__(self, app=None, domain=None, metadata_url=None, settings=None, secret_key=None):
        # Set the domain name, used in the SP's settings and passed to the IDP
        # The domain name should match the Entitiy ID stored with the IDP.
        if not domain:
            raise Exception("A fully-qualified domain name is required.")
        else:
            if not domain.startswith("https://"):
                raise Exception("Domain must be a fully-qualified domain name, starting with 'https://'")
            self.domain = domain

        # Set a default login callback, can be overriden
        self.login_callback = self._login_callback
        
        # Get IDP settings, either dictionary, file or via Metadata endpoint.
        if isinstance(settings, dict):
            self.settings = OneLogin_Saml2_Settings(settings=self._settings_from_dict(settings))    
        elif isinstance(settings, str):
            self.settings = OneLogin_Saml2_Settings(settings=self._settings_from_file(settings))
        else:
            metadata_url = metadata_url or UW_METADATA_ENDPOINT
            self.settings = OneLogin_Saml2_Settings(settings=self._settings_from_url(metadata_url))
        
        # A secret key must be set or given for flask-user sessions
        if "SECRET_KEY" not in app.config:
            if not secret_key:
                raise SecurityException("You must either configure app.config['SECRET_KEY'] or pass secret_key to UWAuthManager")
            else:
                app.config["SECRET_KEY"] = secret_key
        
        # Store the setting in the app config and init the manager
        if app:
            app.config["SAML_SETTINGS"] = self.settings
            self.init_login_manager(app)
            self.init_app(app)

    def init_app(self, app):
        app.saml_manager = self
        app.add_url_rule('/saml/metadata', view_func=SamlMetadata.as_view('metadata'), endpoint='metadata')
        app.add_url_rule('/saml/login', view_func=SamlLogin.as_view('login'), endpoint='login')
        app.add_url_rule('/saml/logout', view_func=SamlLogout.as_view('logout'))
        app.add_url_rule('/saml/acs', view_func=SamlACS.as_view('acs'))

    def init_login_manager(self, app):
        # Setup the flask-user loginmanager to manage server side session
        app.login_manager = LoginManager(app)
        app.login_manager.user_loader = self.load_user

    def load_user(userid):
        return User(userid)

    def _login_callback(self, acs):
        if acs["logged_in"]:
            attributes = dict(acs["attributes"])
            u = User(id=attributes["urn:oid:0.9.2342.19200300.100.1.1"][0])
            login_user(u)
            return redirect(acs["relay_state"])
        else:
            return abort(403)

    def _settings_from_url(self, metadata_url):
        idp_settings = OneLogin_Saml2_IdPMetadataParser.parse_remote(metadata_url)["idp"]
        sp_settings = {
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "assertionConsumerService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTPS-POST",
                    "url": "%s/saml/acs" % self.domain
                },
                "entityId": "%s/saml/metadata" % self.domain,
                "singleLogoutService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "url": "%s/saml/sls" % self.domain
                }
        }
        return {
            "sp": sp_settings,
            "idp": idp_settings
        }

    def _settings_from_file(self, filename):
        raise NotImplementedError

    def _settings_from_dict(self, dictionary):
        raise NotImplementedError

    def _settings(self):
        return {
            "sp": {
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "assertionConsumerService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTPS-POST",
                    "url": "%s/saml/acs" % self.domain
                },
                "entityId": "%s/saml/metadata" % self.domain,
                "singleLogoutService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "url": "%s/saml/sls" % self.domain
                }
            }, 
            "idp": {
                "entityId": "urn:mace:incommon:washington.edu",
                "singleSignOnService": {
                    "url": "https://idp.u.washington.edu/idp/profile/SAML2/Redirect/SSO",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": self.x509cert,
                "attributeConsumingService": {
                    "serviceName": "SP test",
                    "serviceDescription": "SP test serviceDescription"
                }
            }
        }
    def _ssocircle_settings(self):
        return {
            "sp": {
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "assertionConsumerService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTPS-POST",
                    "url": "%s/saml/acs" % self.domain
                },
                "entityId": "%s/saml/metadata" % self.domain,
                "singleLogoutService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "url": "%s/saml/sls" % self.domain
                }
            },
            "idp": {
                "entityId": "https://idp.ssocircle.com",
                "singleLogoutService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "url": "https://idp.ssocircle.com:443/sso/IDPSloRedirect/metaAlias/publicidp"
                },
                "singleSignOnService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "url": "https://idp.ssocircle.com:443/sso/SSORedirect/metaAlias/publicidp"
                },
                "x509cert": "MIIEYzCCAkugAwIBAgIDIAZmMA0GCSqGSIb3DQEBCwUAMC4xCzAJBgNVBAYTAkRFMRIwEAYDVQQKDAlTU09DaXJjbGUxCzAJBgNVBAMMAkNBMB4XDTE2MDgwMzE1MDMyM1oXDTI2MDMwNDE1MDMyM1owPTELMAkGA1UEBhMCREUxEjAQBgNVBAoTCVNTT0NpcmNsZTEaMBgGA1UEAxMRaWRwLnNzb2NpcmNsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCAwWJyOYhYmWZF2TJvm1VyZccs3ZJ0TsNcoazr2pTWcY8WTRbIV9d06zYjngvWibyiylewGXcYONB106ZNUdNgrmFd5194Wsyx6bPvnjZEERny9LOfuwQaqDYeKhI6c+veXApnOfsY26u9Lqb9sga9JnCkUGRaoVrAVM3yfghv/Cg/QEg+I6SVES75tKdcLDTt/FwmAYDEBV8l52bcMDNF+JWtAuetI9/dWCBe9VTCasAr2Fxw1ZYTAiqGI9sW4kWS2ApedbqsgH3qqMlPA7tg9iKy8Yw/deEn0qQIx8GlVnQFpDgzG9k+jwBoebAYfGvMcO/BDXD2pbWTN+DvbURlAgMBAAGjezB5MAkGA1UdEwQCMAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRlMB0GA1UdDgQWBBQhAmCewE7aonAvyJfjImCRZDtccTAfBgNVHSMEGDAWgBTA1nEA+0za6ppLItkOX5yEp8cQaTANBgkqhkiG9w0BAQsFAAOCAgEAAhC5/WsF9ztJHgo+x9KV9bqVS0MmsgpG26yOAqFYwOSPmUuYmJmHgmKGjKrj1fdCINtzcBHFFBC1maGJ33lMk2bM2THx22/O93f4RFnFab7t23jRFcF0amQUOsDvltfJw7XCal8JdgPUg6TNC4Fy9XYv0OAHc3oDp3vl1Yj8/1qBg6Rc39kehmD5v8SKYmpE7yFKxDF1ol9DKDG/LvClSvnuVP0b4BWdBAA9aJSFtdNGgEvpEUqGkJ1osLVqCMvSYsUtHmapaX3hiM9RbX38jsSgsl44Rar5Ioc7KXOOZFGfEKyyUqucYpjWCOXJELAVAzp7XTvA2q55u31hO0w8Yx4uEQKlmxDuZmxpMz4EWARyjHSAuDKEW1RJvUr6+5uA9qeOKxLiKN1jo6eWAcl6Wr9MreXR9kFpS6kHllfdVSrJES4ST0uh1Jp4EYgmiyMmFCbUpKXifpsNWCLDenE3hllF0+q3wIdu+4P82RIM71n7qVgnDnK29wnLhHDat9rkC62CIbonpkVYmnReX0jze+7twRanJOMCJ+lFg16BDvBcG8u0n/wIDkHHitBI7bU1k6c6DydLQ+69h8SCo6sO9YuD+/3xAGKad4ImZ6vTwlB4zDCpu6YgQWocWRXE+VkOb+RBfvP755PUaLfL63AFVlpOnEpIio5++UjNJRuPuAA=",
            }
        }

####
# Views
####

class SamlMetadata(View):
    methods = ['GET']
    def dispatch_request(self):
        saml = SamlRequest(request)
        return saml.generate_metadata()


class SamlLogin(View):
    methods = ['GET']
    def dispatch_request(self):
        saml = SamlRequest(request)
        return redirect(saml.sso())


class SamlLogout(View):
    methods = ['GET']
    def dispatch_request(self):
        saml = SamlRequest(request)
        return redirect(saml.slo())


class SamlACS(View):
    methods = ['POST']
    def dispatch_request(self):
        saml = SamlRequest(request)
        return saml.acs()


####
# SAML logic
####


class SamlRequest(object):

    def __init__(self, request_data):
        self.request = self.prepare_flask_request(request_data)
        self.auth = OneLogin_Saml2_Auth(self.request, old_settings=current_app.config["SAML_SETTINGS"])
        self.errors = []
        self.not_auth_warn = False
        self.success_slo = False
        self.attributes = False
        self.logged_in = False

    def serialize(self):
        return dict(
            errors=self.errors,
            not_auth_warn=self.not_auth_warn,
            success_slo=self.success_slo,
            attributes=self.attributes,
            logged_in=self.logged_in
        )

    def prepare_flask_request(self, request_data):
        url_data = urlparse(request_data.url)
        return {
            'http_host': request_data.host,
            'server_port': url_data.port,
            'script_name': request_data.path,
            'get_data': request_data.args.copy(),
            'post_data': request_data.form.copy()
        }

    def sso(self):
        return_to = self.request["get_data"].get("redirect")
        return self.auth.login(return_to=return_to)

    def slo(self):
        name_id = None
        session_index = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']
        return self.auth.logout(name_id=name_id, session_index=session_index)

    def acs(self):
        self.auth.process_response()
        self.errors = self.auth.get_errors()
        self.not_auth_warn = not self.auth.is_authenticated()
        if len(self.errors) == 0:
            session['samlUserdata'] = self.auth.get_attributes()
            session['samlNameId'] = self.auth.get_nameid()
            session['samlSessionIndex'] = self.auth.get_session_index()
        if 'samlUserdata' in session:
            self.logged_in = True
            if len(session['samlUserdata']) > 0:
                self.attributes = session['samlUserdata'].items()

        attrs = self.serialize()
        attrs["relay_state"] = self.request["post_data"].get("RelayState")
        return current_app.saml_manager.login_callback(attrs)

    def sls(self):
        dscb = lambda: session.clear()
        url = self.auth.process_slo(delete_session_cb=dscb)
        self.errors = self.auth.get_errors()
        if len(self.errors) == 0:
            if url is not None:
                return url
            else:
                self.success_slo = True
        return self.serialize()

    def generate_metadata(self):
        settings = self.auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        if len(errors) == 0:
            resp = make_response(metadata, 200)
            resp.headers['Content-Type'] = 'text/xml'
        else:
            resp = make_response(errors.join(', '), 500)
        return resp