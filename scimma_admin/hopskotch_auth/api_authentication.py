import base64
import datetime
from django.conf import settings
import jwt
import logging
import re
import requests
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView
import rest_authtoken.auth
import rest_authtoken.models
import scramp
from typing import Optional
from urllib.request import parse_http_list
from urllib.parse import urljoin

from .models import RESTAuthToken, SCRAMCredentials, SCRAMExchange, scram_user_lookup, User
from .views import client_ip

logger = logging.getLogger(__name__)

def describe_auth(request) -> str:
    auth = getattr(request, "auth", None)
    if auth:
        if isinstance(auth, SCRAMCredentials):
            return f"Authentication was HTTP SCRAM with credential {auth.username}"
        if isinstance(auth, bytes):
            token = RESTAuthToken.get_token(auth)
            if token is not None:
                return f"Authentication was with token {token}"
            else:
                return "Authentication was with unknown token"
        if isinstance(auth, dict):
            if "jti" in auth: # jti claim is optional
                return f"Authentication was with JWT {auth['jti']} issued by {auth['iss']}"
            else: # we elsewhere require the iss claim, however
                return f"Authentication was with a JWT issued by {auth['iss']}"
    return "Request was not authenticated"

def find_current_credential(request) -> Optional[SCRAMCredentials]:
    auth = getattr(request, "auth", None)
    if auth:
        if isinstance(auth, SCRAMCredentials):
            return auth
        if isinstance(auth, bytes):
            token = RESTAuthToken.get_token(auth)
            if token and token.derived_from:
                return token.derived_from
            else:
                return None
    return None

def do_scram_first(client_first: str):
    """
    Return: If successful, the SCRAMExchange and the SCRAM server object
    """
    # all credentials we issue are SHA-512
    username = ""
    def user_lookup_wrapper(uname):
        nonlocal username
        username = uname
        return scram_user_lookup(username)
    s = scramp.ScramMechanism("SCRAM-SHA-512").make_server(user_lookup_wrapper)
    s.set_client_first(client_first)

    # If scramp did not complain, the exchange can proceed.
    # First, we record the state so that it can be picked up later.
    ex = SCRAMExchange()
    ex.cred = SCRAMCredentials.objects.get(username=username)
    ex.j_nonce = str(s.nonce)
    ex.s_nonce_len = len(str(s.s_nonce))
    ex.client_first = client_first
    ex.began = datetime.datetime.now(datetime.timezone.utc)
    ex.save()
    return (ex,s)

def do_scram_final(client_final: str, sid: Optional[str]=None):
    """
    Return: If successful, the (completed) SCRAMExchange and the SCRAM server
    """
    if sid:
        ex = SCRAMExchange.objects.get(sid=sid)
    else:
        # a bit ugly: To find the previously started exchange session, if any, we need to extract
        # the nonce from the request. We can either reimplement the parsing logic, or underhandedly
        # reach inside of scramp to use its parse function. We do the latter.
        try:
            parsed = scramp.core._parse_message(client_final, "client final", "crp")
        except:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        ex = SCRAMExchange.objects.get(j_nonce=parsed['r'])
    # recreate the SCRAM server state from our stored exchange record
    s = scramp.ScramMechanism("SCRAM-SHA-512").make_server(scram_user_lookup,
                                                           s_nonce=ex.s_nonce())
    s.set_client_first(ex.client_first)
    s.get_server_first()  # waste of time, but scramp requires this to be called
    # if we reach this point, we are ready to process the second half of the exchange
    s.set_client_final(client_final)
    # if scramp hasn't objected, the authentication has now succeeded
    return (ex,s)

def parse_list_header(header: str):
    return [v[1:-1] if v[0] == v[-1] == '"' else v for v in parse_http_list(header)]

def parse_dict_header(header: str):
    def unquote(v: str):
        return v[1:-1] if v[0] == v[-1] == '"' else v
    d = dict()
    for item in parse_list_header(header):
        if '=' in item:
            k, v = item.split('=', 1)
            d[k] = unquote(v)
        else:
            d[k] = None
    return d

class ScramState(object):
    def __init__(self, mech, sid, s):
        self.mech = mech
        self.sid = sid
        self.s = s

class ScramAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # This is a bit tricky, as it doesn't directly have anything to do with SCRAM Auth:
        # If the request wraps one which is already authenticated, we hoist out that authentication
        # information and just return it immediately.
        # This is used by the multi request mechanism to cascade authentication down to sub-requests
        if hasattr(request._request,"user") and request._request.user.is_authenticated \
              and hasattr(request._request,"auth"):
            return (request._request.user, request._request.auth)

        auth_header = get_authorization_header(request)
        if not auth_header or len(auth_header)==0:
            return None
        try:
            auth_header=auth_header.decode("utf-8")
        except:
            raise AuthenticationFailed("Malformed authentication header")

        if not auth_header.upper().startswith("SCRAM-"):
            return None
        m = re.fullmatch("(SCRAM-[A-Z0-9-]+) *([^ ].*)", auth_header, flags=re.IGNORECASE)
        if not m:
            raise AuthenticationFailed("Malformed SCRAM authentication header")
        print("Got attempt at SCRAM auth")
        scram_mech=m.group(1).upper()
        auth_data = parse_dict_header(m.group(2))
        if "data" in auth_data and "sid" in auth_data:
            # If we have both of these we are in the final phase of the SCRAM handshake
            sid = auth_data.get("sid")
            data = auth_data.get("data")
            if not sid or not data:
                raise AuthenticationFailed("Malformed SCRAM authentication header")
            client_final=base64.b64decode(data).decode("utf-8")
            ex,s = do_scram_final(client_final, sid)
            request.META["scram_state"]=ScramState(scram_mech, sid, s)
            return (ex.cred.owner, ex.cred)
        # Otherwise, SCRAM has not yet succeeded
        return None

    def authenticate_header(self, request):
        auth_header = get_authorization_header(request)
        if not auth_header or len(auth_header)==0:
            return "SCRAM-SHA-512"
        try:
            auth_header=auth_header.decode("utf-8")
        except:
            return None
        if auth_header.upper().startswith("SCRAM-"):
            m = re.fullmatch("(SCRAM-[A-Z0-9-]+) *([^ ].*)", auth_header, flags=re.IGNORECASE)
            if not m:
                return "SCRAM-SHA-512"
            scram_mech=m.group(1).upper()
            auth_data = parse_dict_header(m.group(2))
            if not auth_data.get("data", None):
                return "SCRAM-SHA-512"
            client_first=base64.b64decode(auth_data.get("data")).decode("utf-8")
            try:
                # This function will only be called during the SCRAM first phase, so we do that
                ex, s = do_scram_first(client_first)
                sfirst=base64.b64encode(s.get_server_first().encode("utf-8")).decode('utf-8')
                return f"{scram_mech} sid={ex.sid}, data={sfirst}"
            except (ObjectDoesNotExist, scramp.ScramException):
                return None

def set_scram_auth_info_header(get_response):
    def middleware(request):
        response = get_response(request)
        scram_state = request.META.get("scram_state", None)
        if scram_state:
            sfinal=base64.b64encode(scram_state.s.get_server_final().encode("utf-8")).decode('utf-8')
            response["Authentication-Info"]=f"sid={scram_state.sid}, data={sfinal}"
        return response
    return middleware

def find_jwks_url(base_url: str):
    if not base_url.endswith('/'):
        base_url+='/'
    openid_url = urljoin(base_url,".well-known/openid-configuration")
    resp = requests.get(openid_url)
    if not resp.ok:
        logger.error(f"Unable to fetch OpenID configuration from {base_url} "
                     f"(status {resp.status_code}): {resp.text}")
        return None
    try:
        data = resp.json()
    except requests.exceptions.JSONDecodeError:
        logger.error(f"Unable to decode OpenID configuration from {base_url} as JSON")
        return None
    if "jwks_uri" in data and isinstance(data["jwks_uri"], str):
        return data["jwks_uri"]
    logger.error(f"No valid JWKS URI in OpenID configuration from {base_url}")
    return None

jwks_clients = {}
def get_jwt_key(issuer, token):
    if issuer not in settings.TRUSTED_JWT_ISSUERS:
        raise RuntimeError("Untrusted Issuer")
    if issuer not in jwks_clients:
        jwks_url = find_jwks_url(issuer)
        if jwks_url is None:
            raise RuntimeError("Unable to determine JWKS url")
        jwks_clients[issuer] = jwt.PyJWKClient(jwks_url)
    return jwks_clients[issuer].get_signing_key_from_jwt(token)

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # Pass through auth for multi-requests
        # This is used by the multi request mechanism to cascade authentication down to sub-requests
        if hasattr(request._request,"user") and request._request.user.is_authenticated \
              and hasattr(request._request,"auth"):
            return (request._request.user, request._request.auth)
        
        auth_header = get_authorization_header(request)
        if not auth_header or len(auth_header)==0:
            return None
        
        try:
            auth_header=auth_header.decode("utf-8")
        except:
            raise AuthenticationFailed("Malformed authentication header")

        if not auth_header.startswith("Bearer "):
            return None
        raw_token = auth_header[7:]
        
        # we need to parse the claims to figure out the supposed issuer, so we can know against
        # what to validate the token
        try:
            unverified_claims = jwt.decode(raw_token, options={"verify_signature": False})
        except jwt.exceptions.DecodeError:
            # if the data does not decode as a JWT, it's not this class's problem
            print("Token cannot be parsed as a JWT")
            return None
        # check whether necessary claims are missing before bothering about any cryptography
        if not "iss" in unverified_claims:
            raise AuthenticationFailed("Invalid JWT: missing iss claim")
        if not "sub" in unverified_claims:
            raise AuthenticationFailed("Invalid JWT: missing sub claim")
        issuer = unverified_claims["iss"]
        try:
            signing_key = get_jwt_key(issuer, raw_token)
        except jwt.exceptions.PyJWKClientError:
            logger.error(f"Unable to get JWK for issuer {issuer}")
            raise AuthenticationFailed("JWT issuer signing key not found")
        except RuntimeError as err:
            if "Untrusted Issuer" in str(err):
                logger.info(f"Got request with JWT from untrusted issuer {issuer}")
                raise AuthenticationFailed("Invalid JWT: issuer not trusted")
            else:
                raise AuthenticationFailed("JWT validation failed: internal error")
        try:
            claims = jwt.decode(raw_token, signing_key, 
                                algorithms=["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"])
        except Exception as ex:
            logger.info(f"JWT validation failed {ex}")
            raise AuthenticationFailed("Invalid JWT")
        
        subject = claims["sub"]
        search = User.objects.filter(email=subject)
        if not search.exists():
            raise AuthenticationFailed("Unknown user")
        user = search[0]
        return (user, claims)

standard_auth_classes = [ScramAuthentication, 
                         rest_authtoken.auth.AuthTokenAuthentication, 
                         JWTAuthentication]