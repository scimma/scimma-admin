from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse, HttpResponseRedirect
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt

from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

import base64
import jwt

import os.path
import time
from urllib.parse import urlsplit, urlunsplit
import uuid

from .api_authentication import *
from .models import JSONWebKey

# cache the currently valid key locally in memory
current_key = None

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
	JSONWebKey.remove_expired()
	JSONWebKey.ensure_next_key()
	keys = JSONWebKey.objects.all()
	results = []
	for key in keys:
		numbers = key.public_key.public_numbers()
		n = base64.urlsafe_b64encode(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
		e = base64.urlsafe_b64encode(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, 'big')).decode('utf-8').rstrip('=')
		results.append({"kty": "RSA",
		                "use": "sig",
		                "alg": "RS256",
		                "n": n,
		                "e": e,
		                "kid": key.kid,
		                })
	return JsonResponse(data={"keys": results})

class IssueToken(APIView):
	authentication_classes = standard_auth_classes
	permission_classes = [IsAuthenticated]
	
	def post(self, request):
		logger.info(f"{request.user.username} ({request.user.email}) "
		            f"requested a JWT "
		            f"from {client_ip(request)}")
		global current_key
		if current_key is None or not current_key.is_valid:
			current_key = JSONWebKey.get_current()
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
		token = jwt.encode(payload, current_key.private_key, 
		                   headers={"alg": "RS256", "kid": current_key.kid})
		return JsonResponse(data={"access_token": token, "token_type": "bearer", "expires_in": exp_period})
