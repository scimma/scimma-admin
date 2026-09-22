from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse, HttpResponseRedirect
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt

from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

import base64
import jwt

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import os.path
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

from .api_authentication import *

current_key = None

# TODO: We keep track of only one key, and completely replace it. 
# This is not very friendly to anyone downstream, as the old key may be purged before tokens issued
# with it have themselves expired, and tokens issued with the new key can appear before systems
# validating them have a chance to learn about the new key. It would be better to
# - generate and report new keys for some period before starting to issue tokens from them
# - continue to report old keys for as long as tokens issued from the could be valid, after ceasing
#   to issue new tokens from them
# - cache keys in a file so that they do not get replaced suddenly/early when the application
#   restarts
def generate_key(validity_period=7200):
	global current_key
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
	pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
	                                format=serialization.PrivateFormat.TraditionalOpenSSL,
	                                encryption_algorithm=serialization.NoEncryption())
	kid = str(uuid.uuid4())
	expire_time = time.time() + validity_period
	current_key = {
	    "kid": kid,
	    "private_key": private_key,
	    "private_pem": pem.decode('utf-8'),
	    "expiry": expire_time
	}

@require_GET
def openid_config(request: HttpRequest) -> HttpResponse:
    return JsonResponse(data={"issuer": request.build_absolute_uri("..").rstrip("/"), 
                              "jwks_uri": request.build_absolute_uri("../oauth2/certs"),
                              "token_endpoint": request.build_absolute_uri("../oauth2/token"),
                              "id_token_signing_alg_values_supported": ["RS256"],
                              "claims_supported": ["sub", "iat", "exp", "iss"],
                              })


@require_GET
def jwks(request: HttpRequest) -> HttpResponse:
	global current_key
	if current_key is None or current_key["expiry"] < time.time():
		generate_key()
	numbers = current_key["private_key"].public_key().public_numbers()
	n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
	e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
	return JsonResponse(data={"keys": [{"kty": "RSA",
	                                    "use": "sig",
	                                    "alg": "RS256",
	                                    "n": n,
	                                    "e": e,
	                                    "kid": current_key["kid"],
	                                    }]})

class IssueToken(APIView):
	authentication_classes = standard_auth_classes
	permission_classes = [IsAuthenticated]
	
	def post(self, request):
		logger.info(f"{request.user.username} ({request.user.email}) "
		            f"requested a JWT "
		            f"from {client_ip(request)}")
		if current_key is None or current_key["expiry"] < time.time():
			generate_key()
		exp_period = settings.JWT_VALIDITY_PERIOD.total_seconds()
		now = time.time()
		decomp = urlsplit(request.build_absolute_uri())
		# compute updated URL with last two path components removed
		iss_url = urlunsplit(decomp._replace(path=os.path.dirname(os.path.dirname(decomp.path)),
		                                     query="", fragment=""))
		payload = {
		    "sub": request.user.email,
		    "iat": now,
		    "exp": now + exp_period,
		    "iss": iss_url,
		}
		token = jwt.encode(payload, current_key['private_pem'], 
		                   headers={"alg": "RS256", "kid": current_key['kid']})
		return JsonResponse(data={"access_token": token, "token_type": "bearer", "expires_in": exp_period})


