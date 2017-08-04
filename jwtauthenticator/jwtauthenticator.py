from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode
from jose import jwt
from urllib.parse import quote


class JSONWebTokenLoginHandler(BaseHandler):
    def get_relogin_url(self, login_redirect):
        current_base_uri = self.request.protocol + "://" + self.request.host + '/hub/login'
        return login_redirect + quote(current_base_uri)

    def get(self):
        header_name = self.authenticator.header_name
        auth_header_content = self.request.headers.get(header_name, "")
        # if no header was present check for a query param
        if auth_header_content == '':
            query_param_name = self.authenticator.query_param_name
            if query_param_name in self.request.query_arguments and len(
                    self.request.query_arguments[query_param_name]) == 1:
                auth_header_content = 'Bearer ' + self.request.query_arguments[query_param_name][0].decode("utf-8")
        if auth_header_content == '':
            if self.authenticator.login_redirect != None:
                return self.redirect(self.get_relogin_url(self.authenticator.login_redirect))
            else:
                raise web.HTTPError(401)

        signing_certificate = self.authenticator.signing_certificate
        signing_passphrase = self.authenticator.signing_passphrase
        username_claim_field = self.authenticator.username_claim_field
        audience = self.authenticator.expected_audience

        if auth_header_content == "":
            if self.authenticator.login_redirect != None:
                return self.redirect(self.get_relogin_url(self.authenticator.login_redirect))
            else:
                raise web.HTTPError(401)
        else:
            try:
                claims = self.verify_jwt_with_claims(auth_header_content, signing_certificate, signing_passphrase,
                                                     audience)
                username = self.retrieve_username(claims, username_claim_field)
                user = self.user_from_username(username)
                self.set_login_cookie(user)
                return self.redirect(url_path_join(self.hub.server.base_url, 'home'))
            except Exception as ex:
                template = "An exception of type {0} occurred. Arguments:\n{1!r}"
                message = template.format(type(ex).__name__, ex.args)
                self.log.warning("error verifying cert=" + message)
                if self.authenticator.login_redirect != '':
                    return self.redirect(self.get_relogin_url(self.authenticator.login_redirect))
                else:
                    raise web.HTTPError(400)

    @staticmethod
    def verify_jwt_with_claims(auth_header_content, signing_certificate, signing_passphrase, audience):
        json_web_token = str(auth_header_content.split()[1])
        # If no audience is supplied then assume we're not verifying the audience field.
        if audience == "":
            opts = {"verify_aud": False}
        if signing_passphrase != '':
            return jwt.decode(json_web_token, signing_passphrase, algorithms=['HS256'])
        else:
           with open(signing_certificate, 'r') as rsa_public_key_file:
                return jwt.decode(json_web_token, rsa_public_key_file.read(), audience=audience, options=opts)

    @staticmethod
    def retrieve_username(claims, username_claim_field):
        # retrieve the username from the claims
        username = claims[username_claim_field]
        if "@" in username:
            # process username as if email, pull out string before '@' symbol
            return username.split("@")[0]

        else:
            # assume not username and return the user
            return username




class JSONWebTokenAuthenticator(Authenticator):
    """
    Accept the authenticated JSON Web Token from header.
    """
    signing_certificate = Unicode(
        config=True,
        help="""
        The public certificate of the private key used to sign the incoming JSON Web Tokens.

        Should be a path to an X509 PEM format certificate filesystem.
        """
    )

    username_claim_field = Unicode(
        default_value='upn',
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """
    )

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    header_name = Unicode(
        default_value='Authorization',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""")

    signing_passphrase = Unicode(
        default_value='',
        config=True,
        help="""
        The passphrase used to sign the incoming JSON Web Tokens.
        """
    )
    query_param_name = Unicode(
        default_value='jwt_token',
        config=True,
        help="""query param to inspect for the authenticated JSON Web Token.""")

    login_redirect = Unicode(
        default_value='',
        config=True,
        help="""where to redirect user to when they get logged out""")

    def get_handlers(self, app):
        return [
            (r'/login', JSONWebTokenLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()


class JSONWebTokenLocalAuthenticator(LocalAuthenticator):
    """
    Accept the authenticated user name from the REMOTE_USER HTTP header.
    Derived from LocalAuthenticator for use of features such as adding
    local accounts through the admin interface.
    """
    signing_certificate = Unicode(
        config=True,
        help="""
        The public certificate of the private key used to sign the incoming JSON Web Tokens.

        Should be a path to an X509 PEM format certificate filesystem.
        """
    )

    username_claim_field = Unicode(
        default_value='upn',
        config=True,
        help="""
        The field in the claims that contains the user name. It can be either a straight username,
        of an email/userPrincipalName.
        """
    )

    expected_audience = Unicode(
        default_value='',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    header_name = Unicode(
        default_value='Authorization',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token.""")

    signing_passphrase = Unicode(
        default_value='',
        config=True,
        help="""
            The passphrase used to sign the incoming JSON Web Tokens.
            """
    )
    query_param_name = Unicode(
        config=True,
        help="""query param to inspect for the authenticated JSON Web Token.""")

    login_redirect = Unicode(
        config=True,
        help="""where to redirect user to when they get logged out""")

    def get_handlers(self, app):
        return [
            (r'/login', JSONWebTokenLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()
