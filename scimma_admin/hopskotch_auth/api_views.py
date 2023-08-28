import collections
import datetime
from django.core.exceptions import PermissionDenied, BadRequest
from django.db import transaction
from django.db.models import F, Q
from django.http import HttpRequest
from django.urls import resolve, Resolver404
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
import io
import json
from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed
import rest_authtoken.auth
import rest_authtoken.models
import scramp
import traceback
import logging
from urllib.request import parse_http_list
from typing import Optional

from .models import *
from .serializers import v0 as serializers_v0
from .serializers import v1 as serializers_v1
serializers = {
    0: serializers_v0,
    1: serializers_v1,
}
from .views import client_ip
from .auth import HopskotchOIDCAuthenticationBackend

logger = logging.getLogger(__name__)

current_api_version = 1
# All views should receive a 'version' argument in their kwargs, which can be used to implement
# version compatibility. Viewsets may find this in self.kwargs, for use in methods like 
# `get_serializer_class`, which may also need to change depending on the request version. 

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
    return "Request was not authenticated"

class Version(APIView):
    # This is non-sensitive information, which a client may need to read in order to authenticate
    # correctly, so it is not itself subject to authentication
    authentication_classes = []

    def get(self, request):
        return Response(data={"current": current_api_version, "minimum_supported": 0})

def do_scram_first(client_first: str):
    """
    Return: If successful, the SCRAMExchange and the SCRAM server object
    """
    # all credentials we issue are SHA-512
    s = scramp.ScramMechanism("SCRAM-SHA-512").make_server(scram_user_lookup)
    s.set_client_first(client_first)

    # If scramp did not complain, the exchange can proceed.
    # First, we record the state so that it can be picked up later.
    ex = SCRAMExchange()
    ex.cred = SCRAMCredentials.objects.get(username=s.user)
    ex.j_nonce = s.nonce
    ex.s_nonce_len = len(s.s_nonce)
    ex.client_first = client_first
    ex.began = datetime.datetime.now(datetime.timezone.utc)
    ex.save()
    return (ex,s)

def do_scram_final(client_final: str, sid: Optional[str]=None):
    """
    Return: If successful, the (completed) SCRAMExchange and the SCRAM server object
    """
    if sid:
        print("Client supplied sid:",sid)
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
            raise AuthenticationFailed("Malformed SCRAM authentication header")
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
            except (scramp.ScramException):
                raise AuthenticationFailed("SCRAM authentication failed")

def set_scram_auth_info_header(get_response):
	def middleware(request):
		response = get_response(request)
		scram_state = request.META.get("scram_state", None)
		if scram_state:
			sfinal=base64.b64encode(scram_state.s.get_server_final().encode("utf-8")).decode('utf-8')
			response["Authentication-Info"]=f"{scram_state.mech} sid={scram_state.sid}, data={sfinal}"
		return response
	return middleware

def do_scram_first(client_first: str):
    """
    Return: a tuple (sid, server first data)
    """
    # all credentials we issue are SHA-512
    s = scramp.ScramMechanism("SCRAM-SHA-512").make_server(scram_user_lookup)
    s.set_client_first(client_first)

    # If scramp did not complain, the exchange can proceed.
    # First, we record the state so that it can be picked up later.
    ex = SCRAMExchange()
    ex.cred = SCRAMCredentials.objects.get(username=s.user)
    ex.j_nonce = s.nonce
    ex.s_nonce_len = len(s.s_nonce)
    ex.client_first = client_first
    ex.began = datetime.datetime.now(datetime.timezone.utc)
    ex.save()
    return (ex,s)

def do_scram_final(client_final: str, sid: Optional[str]=None):
    """
    Return: If successful, the (completed) SCRAMExchange and the SCRAM server
    """
    if sid:
        print("Client supplied sid:",sid)
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
            raise AuthenticationFailed("Malformed SCRAM authentication header")
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
            except (scramp.ScramException):
                raise AuthenticationFailed("SCRAM authentication failed")

def set_scram_auth_info_header(get_response):
	def middleware(request):
		response = get_response(request)
		scram_state = request.META.get("scram_state", None)
		if scram_state:
			sfinal=base64.b64encode(scram_state.s.get_server_final().encode("utf-8")).decode('utf-8')
			response["Authentication-Info"]=f"{scram_state.mech} sid={scram_state.sid}, data={sfinal}"
		return response
	return middleware

class ScramFirst(APIView):
	# This is an authentication mechanism, so no other authentication should be enforced
    authentication_classes = []

    def post(self, request, version):
        if "client_first" not in request.data:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
        client_first = request.data["client_first"]
        try:
            ex, s = do_scram_first(client_first)
            logger.info(f"Began a SCRAM exchange for user {s.user} from {client_ip(request)}")
            return Response(data={"server_first": s.get_server_first(), "sid": ex.sid}, status=status.HTTP_200_OK)
        except ValueError:
            logger.info(f"Rejected invalid SCRAM request (first) from {client_ip(request)}")
            return Response(data={"error": "Invalid SCRAM request"},
                            status=status.HTTP_401_UNAUTHORIZED)
        except (ObjectDoesNotExist, scramp.ScramException):
            # Authentication has failed, likely due to a malformed SCRAM message, or an unknown
            # username being claimed
            logger.info(f"Rejected invalid SCRAM request (first) from {client_ip(request)}")
            return Response(data={"error": "Invalid SCRAM request"},
                            status=status.HTTP_401_UNAUTHORIZED)

class ScramFinal(APIView):
	# This is an authentication mechanism, so no other authentication should be enforced
    authentication_classes = []
    
    def post(self, request, version):
        if "client_final" not in request.data:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        try:
            ex, s = do_scram_final(request.data["client_final"], sid=request.data.get("sid", None))
        except ObjectDoesNotExist:
            logger.info(f"Rejected invalid SCRAM request (final) from {client_ip(request)}; "
                        "Exchange invlid or expired")
            # We have no record of this SCRAM exchange. Either it timed out or was never begun.
            return Response(status=status.HTTP_400_BAD_REQUEST)
            
        try:
            # Issue a short-lived REST token
            token = RESTAuthToken.create_token_for_user(ex.cred.owner, held_by=ex.cred.owner,
                                                        derived_from=ex.cred)

            # Return to the client the SCRAM server final message, the issued token, and
            # expiration time of the token
            expire_time = RESTAuthToken.get_token(token).created \
                        + settings.REST_TOKEN_TTL
            data = {
                "server_final": s.get_server_final(),
                "sid": ex.sid,
                "token": base64.urlsafe_b64encode(token),
                "token_expires": expire_time
            }
            logger.info(f"Issued REST token to user {ex.cred.username} "
                        f"with expiration time {expire_time}")
            return Response(data=data, status=status.HTTP_200_OK)
        except ValueError:
            logger.info(f"Rejected invalid SCRAM request (final) from {client_ip(request)}")
            return Response(data={"error": "Invalid SCRAM request"},
                            status=status.HTTP_401_UNAUTHORIZED)
        except (ObjectDoesNotExist):
            # Authentication has failed
            logger.info(f"Rejected invalid SCRAM request (final) from {client_ip(request)}")
            return Response(data={"error": "Invalid SCRAM request", 
                                  "server_final": s.get_server_final()}, 
                            status=status.HTTP_401_UNAUTHORIZED)
        finally:
            ex.delete()  # clean up the exchange session record

class MultiRequest(APIView):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]

    def post(self, request, version):
        auth_header_names = ["HTTP_AUTHORIZATION", "HTTP_PROXY_AUTHORIZATION"]

        logger.info(f"{request.user.username} ({request.user.email}) "
                    f"requested to execute a multiplexed batch of requests "
                    f"from {client_ip(request)}")

        if not isinstance(request.data, collections.Mapping):
            return Response(data="Request body must be a mapping",
                            status=status.HTTP_400_BAD_REQUEST)
        response_data = {}
        for key, rdata in request.data.items():
            try:
                if not isinstance(rdata, collections.Mapping) \
                        or "method" not in rdata or not isinstance(rdata["method"], str)\
                        or "path" not in rdata or not isinstance(rdata["path"], str):
                    response_data[key] = {"body":"Invalid request data",
                                          "status":status.HTTP_400_BAD_REQUEST}
                    continue
                sub_request = HttpRequest()
                #sub_request.GET = ???
                #sub_request.POST = ???
                # Leave sub_request.COOKIES empty
                def header_transform(name):
                    uname = name.upper().replace('-','_')
                    if uname == "CONTENT_LENGTH" or uname == "CONTENT_TYPE":
                        return uname
                    return "HTTP_"+uname

                sub_request.META = dict(request.META)
                # strip out all of the original request's Auth data
                for auth_header_name in auth_header_names:
                    if auth_header_name in sub_request.META:
                        del sub_request.META[auth_header_name]
                if "headers" in rdata:
                    if not isinstance(rdata["headers"], collections.Mapping):
                        response_data[key] = {"body":"Invalid request header data",
                                              "status":status.HTTP_400_BAD_REQUEST}
                        continue
                    sr_headers = { header_transform(k):v for k,v in rdata["headers"].items()}
                    sub_request.META.update(sr_headers)
                # overwrite headers which should not be inherited
                sub_request.META["REQUEST_METHOD"] = rdata["method"]
                sub_request.META["REQUEST_URI"] = rdata["path"]
                sub_request.META["PATH_INFO"] = rdata["path"]
                sub_request.META["QUERY_STRING"] = ""  # TODO: add support for this?

                sub_request._read_started = False
                if "body" in rdata:
                    # Icky Hack: DRF wants to decode JSON for us, so we must re-encode the
                    # sub-request's body to be decoded. . . again.
                    # If there's a way to tell DRF to do no parsing on this request (beacuse it
                    # already did it), that could be much more efficient
                    try:
                        raw_body = json.dumps(rdata["body"]).encode("utf-8")
                        sub_request.META["CONTENT_LENGTH"] = len(raw_body)
                        sub_request._stream = io.BytesIO(raw_body)
                    except:
                        response_data[key] = {"body":"Bad request body",
                                              "status":status.HTTP_400_BAD_REQUEST}
                        continue
                else:
                    sub_request.META["CONTENT_LENGTH"] = 0
                    sub_request._stream = io.BytesIO()

                sub_request.path = rdata["path"]
                sub_request.method = rdata["method"]
                sub_request._set_content_type_params(sub_request.META)
                func, args, kwargs = resolve(sub_request.path)
                kwargs['request'] = sub_request
                sub_response = func(*args, **kwargs)
                # Similar to the issue with reserializing the subrequest body above, we must force
                # the sub-response to be 'rendered' to get the actual data, but we must then decode
                # it for inclusion in the full response.
                sub_response.accepted_renderer = JSONRenderer()
                sub_response.accepted_media_type = "application/json"
                sub_response.renderer_context = {}
                sub_response.render()
                response_data[key] = {
                    "body": json.loads(sub_response.content),
                    "headers": sub_response.headers,
                    "status": sub_response.status_code,
                }
            except Resolver404 as e:
                response_data[key] = {"body":"URL not found","status":status.HTTP_404_NOT_FOUND}
                continue
            except Exception as e:
                print("Caught exception:",e)
                print(traceback.format_exc())
                response_data[key] = {"status":status.HTTP_400_BAD_REQUEST}
                continue

        return Response(data=response_data,
                        status=status.HTTP_200_OK)

class TokenForOidcUser(APIView):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]
    # TODO !!! must also have special authority to use this privileged feature
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def post(self, request, version):
        if "sub" in request.data:
            username = request.data["sub"]
        elif "vo_person_id" in request.data:
            username = request.data["vo_person_id"]
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        username = request.data["vo_person_id"]
        
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist:
            return Response(data={"error": "Unknown username"},
                            status=status.HTTP_404_NOT_FOUND)
        try:
            # Issue a short-lived REST token
            # Note that we set derived_from to None because we do not want this token to be associated
            # back to the admin user credential which created it, as that would cause odd effects
            # if it is used with the current_credential routes.
            token = RESTAuthToken.create_token_for_user(user, held_by=request.user, derived_from=None)

            # Return to the client the the issued token and expiration time of the token
            expire_time = RESTAuthToken.get_token(token).created \
                        + settings.REST_TOKEN_TTL
            data = {
                "token": base64.urlsafe_b64encode(token),
                "token_expires": expire_time
            }
            logger.info(f"Issuing a REST token to {request.user.username} ({request.user.email}) "
                        f"at {client_ip(request)} "
                        f"to act on behalf of {user.username} (user.email)")
            return Response(data=data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response(data={"error": "Failed to issue a REST token"},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class UserViewSet(viewsets.ModelViewSet):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    queryset = User.objects.all()

    def __init__(self, *args, **kwargs):
        self.get_lookup_field = self._get_lookup_field
        super().__init__(*args, **kwargs)

    def get_serializer_class(self):
        return serializers[self.kwargs.get("version",current_api_version)].UserSerializer

    @staticmethod
    def get_lookup_field(version=current_api_version):
        if version == 0:
            return "pk"
        if version >= 1:
            return "username"

    def _get_lookup_field(self):
        return UserViewSet.get_lookup_field(self.kwargs.get("version",current_api_version))

    def get_object(self):
        self.lookup_field = self.get_lookup_field()
        return super().get_object()

    def get_target_descriptor(self, kwargs):
        return kwargs.get(self.get_lookup_field(),'<missing>')
    
    def list(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    "requested to list all users "
                    f"from {client_ip(request)}; {describe_auth(request)}")
        return super().list(request, *args, **kwargs)
    
    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested information about user {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def retrieve_current(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested information about themself "
                    f"from {client_ip(request)}; {describe_auth(request)}")
        lf = self.get_lookup_field()
        # Co-opt the lookup infrastructure to point at the user making the request
        self.kwargs[lf] = getattr(request.user, lf)
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to create new user {request.data.get('vo_person_id','<missing>')} "
                    f"from {client_ip(request)}")
        
        # TODO !!! must also have special authority to use this privileged feature
        if not self.request.user.is_staff:
                raise PermissionDenied
        
        if "sub" not in request.data:
            return Response(data={"error": "sub missing"},
                            status=status.HTTP_400_BAD_REQUEST)
        if "is_member_of" not in request.data:
            return Response(data={"error": "is_member_of missing"},
                            status=status.HTTP_400_BAD_REQUEST)
        if "email" not in request.data and "email_list" not in request.data:
            return Response(data={"error": "email/email_list missing"},
                            status=status.HTTP_400_BAD_REQUEST)

        try:
            auth_back = HopskotchOIDCAuthenticationBackend()
            auth_back.verify_claims(request.data)
            user = auth_back.create_user(request.data)
            serializer = self.get_serializer(user)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data,
                            status=status.HTTP_201_CREATED, headers=headers)
        except PermissionDenied as ex:
            return Response(data={"error": ex.args},
                            status=status.HTTP_400_BAD_REQUEST)
		
        return Response(status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to delete user {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        # only staff should delete users
        if not self.request.user.is_staff:
            raise PermissionDenied
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        raise PermissionDenied

    
class SCRAMCredentialsViewSet(viewsets.ModelViewSet):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def __init__(self, *args, **kwargs):
        self.get_lookup_field = self._get_lookup_field
        super().__init__(*args, **kwargs)

    def get_serializer_class(self):
        return serializers[self.kwargs.get("version",current_api_version)].SCRAMCredentialsSerializer

    @staticmethod
    def get_lookup_field(version=current_api_version):
        if version == 0:
            return "pk"
        if version >= 1:
            return "username"

    def _get_lookup_field(self):
        return SCRAMCredentialsViewSet.get_lookup_field(self.kwargs.get("version",current_api_version))

    def get_queryset(self):
        queryset = SCRAMCredentials.objects.all()

        # if specified, pull out only the credentials belonging to a specific user
        if "user" in self.kwargs:
            owner = self.kwargs["user"]
            
            version = self.kwargs.get("version",current_api_version)
            if version >= 1:
                search = User.objects.filter(username=owner)
                if not search.exists():
                    raise BadRequest
                owner = search[0]

            # non-staff users may not view other users' credentials
            if not self.request.user.is_staff and owner!=self.request.user.id:
                raise PermissionDenied

            queryset = queryset.filter(owner=owner)

        else: # only staff members may see the full, unfiltered list
            if not self.request.user.is_staff:
                raise PermissionDenied

        return queryset

    def get_object(self):
        self.lookup_field = self.get_lookup_field()
        return super().get_object()

    def get_target_descriptor(self, kwargs):
        return kwargs.get(self.get_lookup_field,'<missing>')

    def list(self, request, *args, **kwargs):
        if "user" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list SCRAM credentials belonging to user {kwargs['user']} "
                    f"from {client_ip(request)}")
        else:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                        "requested to list SCRAM credentials belonging to all users "
                        f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def list_for_current_user(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list SCRAM credentials belonging to themself "
                    f"from {client_ip(request)}")
        version = self.kwargs.get("version",current_api_version)
        self.kwargs["user"] = getattr(request.user, UserViewSet.get_lookup_field(version))
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of SCRAM credential {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def retrieve_current(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of the SCRAM credential currently in use "
                    f"from {client_ip(request)}")
        cred = find_current_credential(request)
        if not cred:
            raise BadRequest("No SCRAM credential associated with this request")
        lf = self.get_lookup_field()
        # Co-opt the lookup infrastructure to point at this particular credential
        self.kwargs[lf] = getattr(cred, lf)
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        bundle = new_credentials(request.user)
        
        logger.info(f"Created new credential {bundle.username} on behalf of user "
                f"{request.user.username} ({request.user.email}) from {client_ip(request)}")
        
        try:
            if "description" in request.data:
                bundle.creds.description = request.data["description"]
                bundle.creds.save()
        except:
            logger.info(f"Failed to set SCRAM credential description")
        
        data = {
            "username": bundle.username,
            "password": bundle.password,
            "pk": bundle.creds.pk
        }
        
        return Response(data=data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to delete SCRAM credential {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to update SCRAM credential {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
    
        instance = self.get_object()
        # Only admins and owners can change credentials
        if not request.user.is_staff and request.user!=instance.owner:
            raise PermissionDenied("Only staff and credential owners can update credentials")
        
        # Only admins can manipulate the suspension flag
        if "suspended" in request.data and not request.user.is_staff:
            raise PermissionDenied("Only staff can change credential suspension")

        # avoid invoking the overridden self.update and making logging confusing
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

class GroupViewSet(viewsets.ModelViewSet):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    # all users are allowed to see the full list of groups
    queryset = Group.objects.all()

    def get_serializer_class(self):
        return serializers[self.kwargs.get("version",current_api_version)].GroupSerializer

    def get_object(self):
        version = self.kwargs.get("version",current_api_version)
        if version > 0:
            self.lookup_field = "name"
        return super().get_object()

    def get_target_descriptor(self, kwargs):
        version = self.kwargs.get("version",current_api_version)
        if version == 0:
            return kwargs.get('pk','<missing>')
        else:
            return kwargs.get('name','<missing>')

    def list(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    "requested to list all groups "
                    f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of group {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to create a group "
                    f"from {client_ip(request)}")
        # only staff should create groups
        if not self.request.user.is_staff:
            raise PermissionDenied
        return super().create(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to delete group {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        # only staff should delete groups
        if not self.request.user.is_staff:
            raise PermissionDenied
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to update group {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
    
        group = self.get_object()
        # Only admins and owners can change credentials
        if not request.user.is_staff and not is_group_owner(self.request.user.id, group):
            raise PermissionDenied("Only staff and group owners can update groups")

        # avoid invoking the overridden self.update and making logging confusing
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

class GroupMembershipViewSet(viewsets.ModelViewSet):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get_serializer_class(self):
        return serializers[self.kwargs.get("version",current_api_version)].GroupMembershipSerializer

    def get_queryset(self):
        queryset = GroupMembership.objects.all()
        # if specified, pull out only the memberships of a specific user
        if "user" in self.kwargs:
            target_user = self.kwargs["user"]
            
            version = self.kwargs.get("version",current_api_version)
            if version >= 1:
                search = User.objects.filter(username=target_user)
                if not search.exists():
                    raise BadRequest
                target_user = search[0]
            
            # non-staff users may not view other users' group memberships
            if not self.request.user.is_staff and target_user!=self.request.user.id:
                raise PermissionDenied

            queryset = queryset.filter(user=target_user)

        # if specified, pull out only the memberships of a specific group
        if "group" in self.kwargs:
            group = self.kwargs["group"]

            version = self.kwargs.get("version",current_api_version)
            if version >= 1:
                search = Group.objects.filter(name=group)
                if not search.exists():
                    raise BadRequest
                group = search[0]

            # non-staff members may not examine the membership lists of groups to which they do not belong
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, group):
                raise PermissionDenied

            queryset = queryset.filter(group=group)

        # only staff members may see the full, unfiltered list
        if not self.request.user.is_staff and "user" not in self.kwargs and "group" not in self.kwargs:
            raise PermissionDenied
            
        return queryset

    def get_target_descriptor(self, kwargs):
        version = self.kwargs.get("version",current_api_version)
        if version == 0:
            return kwargs.get('pk','<missing>')
        else:
            return kwargs.get('id','<missing>')

    def list(self, request, *args, **kwargs):
        if "user" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list user {kwargs['user']}'s group memberships "
                    f"from {client_ip(request)}")
        elif "group" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list group {kwargs['group']}'s memberships "
                    f"from {client_ip(request)}")
        else:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                        "requested to list all group memberships "
                        f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def list_for_current_user(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list their own group memberships "
                    f"from {client_ip(request)}")
        version = self.kwargs.get("version",current_api_version)
        self.kwargs["user"] = getattr(request.user, UserViewSet.get_lookup_field(version))
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of group membership {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to add a member to group {kwargs.get('group','<missing>')} "
                    f"from {client_ip(request)}")
        serializer = GroupMembershipCreationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        print(f"validated_data: {serializer.validated_data}")
        group = serializer.validated_data['group']
        target_user = serializer.validated_data['user']
        
        if "group" not in kwargs:
        	raise BadRequest
        # Not strictly required, but to keep things clear, require that the group to which the
        # mmebership would be added match what was specified in the URL.
        version = self.kwargs.get("version",current_api_version)
        if version == 0 and group.id!=kwargs["group"]:
            raise BadRequest
        if version > 0 and group.name!=kwargs["group"]:
            raise BadRequest
        
        # Only admins and group owners can change group memberships
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, group.id):
            raise PermissionDenied
        
        # Forbid creation of redundant enries
        if is_group_member(target_user.id, group.id):
            raise BadRequest(f"User {target_user} is already a member of group {group}")
        
        membership = serializer.save()
        
        return_serializer = self.get_serializer(membership)
        headers = self.get_success_headers(return_serializer.data)
        return Response(return_serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to delete group membership {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        instance = self.get_object()
        
        # Only admins and group owners can change group memberships
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, instance.group.id):
            raise PermissionDenied
        
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to update membership {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        instance = self.get_object()
        # Only admins and group owners can change group memberships
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, instance.group.id):
            raise PermissionDenied
        
        # avoid invoking the overridden self.update and making logging confusing
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

class KafkaTopicViewSet(viewsets.ModelViewSet):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def __init__(self, *args, **kwargs):
        self.get_lookup_field = self._get_lookup_field
        super().__init__(*args, **kwargs)

    @staticmethod
    def get_lookup_field(version=current_api_version):
        if version == 0:
            return "pk"
        if version >= 1:
            return "name"

    def _get_lookup_field(self):
        return KafkaTopicViewSet.get_lookup_field(self.kwargs.get("version",current_api_version))
    
    def get_queryset(self):
        queryset = KafkaTopic.objects.all()
        
        # if specified, pull out only the topics owned by a specific group
        if "owning_group" in self.kwargs:
            group = self.kwargs["owning_group"]
            
            version = self.kwargs.get("version",current_api_version)
            if version >= 1:
                search = Group.objects.filter(name=group)
                if not search.exists():
                    raise BadRequest
                group = search[0]

            # non-staff users may not generally view topics owned by groups to which they do not belong
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, group):
                raise PermissionDenied
            
            queryset = queryset.filter(owning_group=group)

        elif not self.request.user.is_staff:
            # non-staff users can only see topics to which they have been granted access
            # this includes topics which are public, 
            # and topics for which access has been granted to a group to which the user belongs.
            public_topics = KafkaTopic.objects.filter(publicly_readable=True)
            accessible_topics = KafkaTopic.objects.filter(id__in=GroupKafkaPermission.objects.filter(principal__in=GroupMembership.objects.filter(user=self.request.user).values("group")).values("topic"))
            
            queryset = public_topics | accessible_topics
            
        return queryset

    def get_object(self):
        self.lookup_field = self.get_lookup_field()
        return super().get_object()

    def get_serializer_class(self):
        if getattr(self.request, "user", None) and self.request.user.is_staff:
            return serializers[self.kwargs.get("version",current_api_version)].KafkaTopicAdminSerializer
        # plain serializer for regular users
        return serializers[self.kwargs.get("version",current_api_version)].KafkaTopicSerializer

    def get_target_descriptor(self, kwargs):
        return kwargs.get(self.get_lookup_field(),'<missing>')

    def list(self, request, *args, **kwargs):
        if "owning_group" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list topics owned by group {kwargs['owning_group']} "
                    f"from {client_ip(request)}")
        else:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                        "requested to list all Kafka topics "
                        f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of Kafka topic {self.get_target_descriptor(kwargs)} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        if "owning_group" not in self.kwargs:
            raise BadRequest
        
        data = request.data
        version = self.kwargs.get("version",current_api_version)
        if version == 0:
            group_id = self.kwargs["owning_group"]

            logger.info(f"User {request.user.username} ({request.user.email}) "
                        f"requested to create a Kafka topic owned by group {group_id} "
                        f"from {client_ip(request)}")

            try:
                group = Group.objects.get(id=group_id)
                data["owning_group"] = group.id
            except ObjectDoesNotExist as dne:
                return Response(status=status.HTTP_400_BAD_REQUEST)
        elif version == 1:
            group_name = self.kwargs["owning_group"]

            logger.info(f"User {request.user.username} ({request.user.email}) "
                        f"requested to create a Kafka topic owned by group {group_name} "
                        f"from {client_ip(request)}")

            try:
                group = Group.objects.get(name=group_name)
                data["owning_group"] = group.name
            except ObjectDoesNotExist as dne:
                return Response(status=status.HTTP_400_BAD_REQUEST)

        # non-staff users may not create topics owned by groups of which they are not owners
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, group.id):
            raise PermissionDenied

        serializer = serializers[self.kwargs.get("version",current_api_version)].KafkaTopicCreationSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            topic = serializer.save()
            GroupKafkaPermission.objects.create(principal=group, topic=topic, operation=KafkaOperation.All)
        return_serializer = self.get_serializer(topic)
        headers = self.get_success_headers(return_serializer.data)
        return Response(
            return_serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to delete Kafka topic {self.get_target_descriptor(kwargs)} "
                    f"owned by group {kwargs.get('owning_group','<unknown>')} "
                    f"from {client_ip(request)}")

        instance = self.get_object()
        # Only group owners and admins can delete topics
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, instance.owning_group):
            raise PermissionDenied
        
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to update Kafka topic {self.get_target_descriptor(kwargs)} "
                    f"owned by group {kwargs.get('owning_group','<unknown>')} "
                    f"from {client_ip(request)}")
        instance = self.get_object()
        # Only admins and group owners can change topics
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, instance.owning_group):
            raise PermissionDenied
        
        # avoid invoking the overridden self.update and making logging confusing
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

class GroupKafkaPermissionViewSet(viewsets.ModelViewSet):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        return serializers[self.kwargs.get("version",current_api_version)].GroupKafkaPermissionSerializer

    def get_queryset(self):
        # TODO: switch between group pks and group names
        queryset = GroupKafkaPermission.objects.all()
        all = True

        # if specified, pull out permissions granted by the specified group
        if "granting_group" in self.kwargs:
            group = self.kwargs["granting_group"]

            version = self.kwargs.get("version",current_api_version)
            if version >= 1:
                search = Group.objects.filter(name=group)
                if not search.exists():
                    raise BadRequest
                group = search[0]
            
            # non-staff users may not query the full set of permissions granted by groups
            # to which they do not belong
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, group):
                raise PermissionDenied
            
            queryset = queryset.filter(topic__owning_group=group)
            all = False
        
        # if specified, pull out permissions granted by the specified group
        if "subject_group" in self.kwargs:
            group = self.kwargs["subject_group"]

            version = self.kwargs.get("version",current_api_version)
            if version >= 1:
                search = Group.objects.filter(name=group)
                if not search.exists():
                    raise BadRequest
                group = search[0]
            
            # non-staff users may not query the full set of permissions granted to groups
            # to which they do not belong
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, group):
                raise PermissionDenied
            
            queryset = queryset.filter(principal=group)
            all = False

        # if specified, pull out permissions relating to the specified topic
        if "topic" in self.kwargs:
            topic = self.kwargs["topic"]

            version = self.kwargs.get("version",current_api_version)
            if version >= 1:
                search = KafkaTopic.objects.filter(name=topic)
                if not search.exists():
                    raise BadRequest
                topic = search[0]

            # non-staff users may not query the full set of permissions to a topic if they do not
            # belong to the group which owns it
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, topic.owning_group):
                raise PermissionDenied

            queryset = queryset.filter(topic=topic)
            all = False

        # only staff members may see the unrestricted list
        if all and not self.request.user.is_staff:
            raise PermissionDenied

        return queryset

    def list(self, request, *args, **kwargs):
        msg = f"User {request.user.username} ({request.user.email}) " \
              "requested to list group permissions"
        if "granting_group" in kwargs:
            msg += f" granted by group {kwargs['granting_group']}"
        if "subject_group" in kwargs:
            msg += f" granted to group {kwargs['subject_group']}"
        if "topic" in kwargs:
            msg += f" associated with topic {kwargs['topic']}"
        msg += f" from {client_ip(request)}"
        logger.info(msg)
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of group permission {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to create a group permission "
                    f"from {client_ip(request)}")
        serializer = GroupKafkaPermissionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        topic = serializer.validated_data['topic']
        
        # Only admins and group owners can grant group permissions
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, topic.owning_group):
            raise PermissionDenied
        
        perm = add_kafka_permission_for_group(serializer.validated_data['principal'].id,
                                              serializer.validated_data['topic'],
                                              serializer.validated_data['operation'])
        
        # the result object may not be exactly the one requested, so re-serialize explicitly
        result_data = self.get_serializer(perm).data
        headers = self.get_success_headers(result_data)
        return Response(result_data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to remove group permission {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        
        perm = self.get_object()
        # Only admins and owners of the granting group can revoke group permissions
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, perm.topic.owning_group):
            raise PermissionDenied
        
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        raise PermissionDenied

class CredentialKafkaPermissionViewSet(viewsets.ModelViewSet):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        return serializers[self.kwargs.get("version",current_api_version)].CredentialKafkaPermissionSerializer

    def get_queryset(self):
        queryset = CredentialKafkaPermission.objects.all()

        if "cred" in self.kwargs:
            cred = self.kwargs["cred"]

            version = self.kwargs.get("version",current_api_version)
            search = SCRAMCredentials.objects.filter(
                **{SCRAMCredentialsViewSet.get_lookup_field(version): cred})
            if not search.exists():
                raise BadRequest
            cred = search[0]

            # non-staff users may not query the properties of credentials they do not own
            if not self.request.user.is_staff and cred.owner!=self.request.user:
                raise PermissionDenied

            queryset = queryset.filter(principal=cred)
        elif not self.request.user.is_staff:
            # only staff users may query the full list
            raise PermissionDenied

        return queryset

    def list(self, request, *args, **kwargs):
        if "cred" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list permissions attatched to SCRAM credential {kwargs['cred']} "
                    f"from {client_ip(request)}")
        else:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                        "requested to list all SCRAM credential permissions "
                        f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def list_for_current_credential(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list permissions attatched to the current SCRAM credential"
                    f"from {client_ip(request)}; {describe_auth(request)}")
        version = self.kwargs.get("version",current_api_version)
        cred = find_current_credential(request)
        if not cred:
            raise BadRequest("No SCRAM credential associated with this request")
        self.kwargs["cred"] = getattr(cred, SCRAMCredentialsViewSet.get_lookup_field(version))
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of SCRAM credential permission {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to add a permission to SCRAM credential {kwargs.get('cred','<missing>')} "
                    f"from {client_ip(request)}")
        serializer = CredentialKafkaPermissionCreationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        principal = serializer.validated_data["principal"]
        topic = serializer.validated_data["topic"]
        operation = serializer.validated_data["operation"]

        # Only credential owners and admins should be able to add permissions to a credential
        if not self.request.user.is_staff and request.user!=principal.owner:
            raise PermissionDenied

        # Avoid creating duplicates
        # General case
        existing_perm = CredentialKafkaPermission.objects.filter(principal=principal, 
                                                                 topic=topic,
                                                                 operation=KafkaOperation.All)
        if existing_perm.exists():
        	return Response(result_data, status=status.HTTP_200_OK)
        # Specific case
        existing_perm = CredentialKafkaPermission.objects.filter(principal=principal, 
                                                                 topic=topic,
                                                                 operation=operation)
        if existing_perm.exists():
            result_data = self.get_serializer(list(existing_perm)[0]).data
            headers = self.get_success_headers(result_data)
            return Response(result_data, status=status.HTTP_200_OK, headers=headers)
        
        notional_perm = CredentialKafkaPermission(principal=principal, topic=topic, operation=operation)
        # Do not 'create' notional_perm into the database yet as we have not set its parent permission,
        # and may or may not find a suitable value for that

        # Try to discover some group permission which can serve as a basis for this credential permission
        group_perms = GroupKafkaPermission.objects.filter(models.Q(operation=KafkaOperation.All) |
                                                          models.Q(operation=operation),
                                                          topic=topic
                                                          )
        base_perm: Optional[GroupKafkaPermission] = None
        for group_perm in group_perms:
            if is_group_member(request.user.id, group_perm.principal.id):
                base_perm = group_perm
                break

        if base_perm is None:
            raise PermissionDenied

        notional_perm.parent = base_perm
        notional_perm.save()

        result_data = self.get_serializer(notional_perm).data
        headers = self.get_success_headers(result_data)
        return Response(result_data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to remove permission {kwargs.get('pk','<missing>')} "
                    f"from SCRAM credential {kwargs.get('cred','<missing>')} "
                    f"from {client_ip(request)}")
        perm = self.get_object()
        cred = SCRAMCredentials.objects.get(id=perm.principal)

        # Only credential owners and admins should be able to remove permissions from a credential
        if not self.request.user.is_staff and request.user!=cred.owner:
            raise PermissionDenied

        return super().destroy(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        raise PermissionDenied

    def partial_update(self, request, *args, **kwargs):
        raise PermissionDenied

class CredentialPermissionsForTopic(APIView):
    authentication_classes = [ScramAuthentication, rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, already_logged=False, *args, **kwargs):
        if not already_logged:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                        f"requested to list Kafka permissions for topic {kwargs.get('topic','<missing>')} "
                        f"associated with SCRAM credential {kwargs.get('cred','<missing>')} "
                        f"from {client_ip(request)}")
        version = self.kwargs.get("version",current_api_version)

        cred = kwargs["cred"]
        search = SCRAMCredentials.objects.filter(**{SCRAMCredentialsViewSet.get_lookup_field(version): cred})
        if not search.exists():
            raise BadRequest
        cred = search[0]

        topic = self.kwargs["topic"]
        search = KafkaTopic.objects.filter(**{KafkaTopicViewSet.get_lookup_field(version): topic})
        if not search.exists():
            raise BadRequest
        topic = search[0]

        perms = set()
        if topic.publicly_readable:
            perms.add(KafkaOperation.Read)

        queryset = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic)
        for permission in queryset:
            perms.add(permission.operation)

        serializer = serializers[self.kwargs.get("version",current_api_version)].ReadableEnumField(KafkaOperation)

        return Response(data={"allowed_operations": [serializer.to_representation(p) for p in perms]})

class CurrentCredentialPermissionsForTopic(CredentialPermissionsForTopic):
    def get(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list Kafka permissions for topic {kwargs.get('topic','<missing>')} "
                    f"associated with the current SCRAM credential "
                    f"from {client_ip(request)}; {describe_auth(request)}")
        version = self.kwargs.get("version",current_api_version)
        cred = find_current_credential(request)
        if not cred:
            raise BadRequest("No SCRAM credential associated with this request")
        kwargs["cred"] = getattr(cred, SCRAMCredentialsViewSet.get_lookup_field(version))
        return super().get(request, already_logged=True, *args, **kwargs)