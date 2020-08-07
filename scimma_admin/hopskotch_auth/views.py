from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.views.decorators.http import require_POST
from wsgiref.util import FileWrapper
from io import StringIO

from .models import new_credentials, delete_credentials

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
    bundle = new_credentials(request.user)
    return render(
        request, 'hopskotch_auth/create.html',
        dict(username=bundle.username, password=bundle.password),
    )


@login_required
def delete(request):
    cred_username = request.GET.get('cred_username')
    if cred_username is None:
        logger.error(f"missing cred_username parameter in delete request")
        messages.error(request, "missing cred_username parameter in delete request")
        return redirect("index")

    try:
        delete_credentials(request.user, cred_username)
    except ObjectDoesNotExist:
        messages.error(request, "no such username found for your user")
        return redirect("index")
    except MultipleObjectsReturned:
        messages.error(request, "Multiple credentials found with that username. Please report this to swnelson@uw.edu.")
        return redirect("index")

    logger.info(f"deleted creds associated with username: {cred_username}")
    messages.info(request, f"deleted credentials with username {cred_username}")

    return redirect("index")

@login_required
def download(request):
    myfile = StringIO()
    myfile.write("username,password\n")
    myfile.write(f"{request.POST['username']},{request.POST['password']}")       
    myfile.flush()
    myfile.seek(0) # move the pointer to the beginning of the buffer
    response = HttpResponse(FileWrapper(myfile), content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename=hop-credentials.csv'    
    return response
