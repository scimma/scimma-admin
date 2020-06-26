from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.views.decorators.http import require_POST

from .models import new_credentials

import logging

logger = logging.getLogger(__name__)


@login_required
def index(request):
    credentials = request.user.scramcredentials_set.all()
    return render(
        request, 'hopskotch_auth/index.html',
        dict(credentials=credentials),
    )


def login(request):
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    return render(request, 'hopskotch_auth/login.html',)


def logout(request):
    return HttpResponse("you're logged out!")


@require_POST
@login_required
def create(request):
    creds, username, rand_password = new_credentials(request.user)
    return render(
        request, 'hopskotch_auth/create.html',
        dict(username=username, password=rand_password),
    )



@login_required
def delete(request):
    return HttpResponse("not implemented")
