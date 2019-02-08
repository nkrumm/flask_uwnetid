import sys
import logging
logging.basicConfig(
    stream=sys.stderr,
    format='%(asctime)s %(levelname)s %(module)s %(lineno)s %(message)s',
    level=logging.INFO)

log = logging.getLogger(__name__)

from urllib.parse import urlparse

from flask import (
    redirect, abort, request, current_app,
    make_response, session, url_for)

from flask.views import View
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser


try:
    # This is wrapped in a try-block as flask_login may not be needed.
    from flask_login import (
        LoginManager, login_user, login_required, UserMixin
    )

    class User(UserMixin):
        id_urn = "urn:oid:0.9.2342.19200300.100.1.1"
        groups_urn = "urn:oid:1.3.6.1.4.1.5923.1.5.1.1"
        def __init__(self, attributes):
            self.id = attributes[self.id_urn][0]
            if self.groups_urn in attributes:
                self.groups = {g.split(":")[-1] for g in attributes[self.groups_urn]}
            else:
                self.groups = set()

except:
    log.warn("Could not load flask_login or create User object. This may not be necessary "
             "if a `login_callback` is provided to UWAuthManager.")


class SecurityException(Exception):
    pass


UW_METADATA_ENDPOINT = 'https://idp.u.washington.edu/metadata/idp-metadata.xml'

class UWAuthManager(object):

    def __init__(self, app=None, domain=None, metadata_url=None,
                 x509cert=None, private_key=None, settings=None, secret_key=None,
                 strict=True, debug=False, login_callback=None, use_flask_login=True,
                 enable_two_factor=False):
        # SECURITY NOTE: `strict` should be set to True for production use!
        # Note that debug can be used in conjuction with strict=True.
        self.strict = strict
        self.debug = debug
        self.enable_two_factor = enable_two_factor

        # Set the domain name, used in the SP's settings and passed to the IDP
        # The domain name should match the Entitiy ID stored with the IDP.
        if not domain:
            raise Exception("A fully-qualified domain name is required.")
        else:
            if not domain.startswith("https://"):
                raise Exception("Domain must be a fully-qualified domain name, starting with 'https://'")
            self.domain = domain

        # set up the certificate
        if not x509cert or not private_key:
            raise Exception("A X509 certificate and private key is required.")
        elif "PRIVATE" in x509cert:
            raise Exception("Certificate should NOT be the private key.")
        else:
            self.x509cert = x509cert
            self.private_key = private_key

        # Set a default login callback, can be overriden
        self.login_callback = login_callback or self._login_callback

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
            if use_flask_login:
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
        login_manager = LoginManager()
        login_manager.init_app(app)
        login_manager.user_loader(self.load_user)
        login_manager.unauthorized_handler(self.handle_login_redirect)

    def load_user(self, userid):
        return User(userid)

    def handle_login_redirect(self):
        return redirect(url_for('login', redirect=request.path))

    def _login_callback(self, acs):
        if acs["logged_in"]:
            attributes = dict(acs["attributes"])
            u = User(attributes)
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
                "x509cert": self.x509cert,
                "privateKey": self.private_key,
                "entityId": "%s/saml/metadata" % self.domain,
                "singleLogoutService": {
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "url": "%s/saml/sls" % self.domain
                }
        }
        security_settings = {
            # requestedAuthnContext needs to be OFF when 2FA is enabled. 
            "requestedAuthnContext": not self.enable_two_factor
        }
        return {
            "strict": self.strict,
            "debug": self.debug,
            "sp": sp_settings,
            "idp": idp_settings,
            "security": security_settings,
        }

    def _settings_from_file(self, filename):
        raise NotImplementedError

    def _settings_from_dict(self, dictionary):
        raise NotImplementedError

    def protect_all_views(self, app):
        """Require login for all views other than saml endpoints.

        """
        saml_endpoints = {'metadata', 'login', 'logout', 'acs'}
        for view_func in app.server.view_functions:
            if view_func not in saml_endpoints:
                app.server.view_functions[view_func] = \
                    login_required(app.server.view_functions[view_func])
        return app


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

    def prepare_flask_request(self, request):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        url_data = urlparse(request.url)
        return {
            'https': 'on',#  TODO: use HTTP_X_FORWARDED here?
            'http_host': request.host,
            'server_port': url_data.port,
            'script_name': request.path,
            'get_data': request.args.copy(),
            'post_data': request.form.copy(),
            'query_string': request.query_string
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
        return_to = self.request["get_data"].get("redirect")
        return self.auth.logout(name_id=name_id, session_index=session_index, return_to=return_to)

    def acs(self):
        self.auth.process_response()
        self.errors = self.auth.get_errors()
        self.not_auth_warn = not self.auth.is_authenticated()
        if len(self.errors) == 0:
            session['samlUserdata'] = self.auth.get_attributes()
            session['samlNameId'] = self.auth.get_nameid()
            session['samlSessionIndex'] = self.auth.get_session_index()
        else:
            log.error(self.errors)
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
        else:
            log.error(self.errors)

        return self.serialize()

    def generate_metadata(self):
        settings = self.auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        if len(errors) == 0:
            resp = make_response(metadata, 200)
            resp.headers['Content-Type'] = 'text/xml'
        else:
            log.error(errors)

            resp = make_response(errors.join(', '), 500)
        return resp
