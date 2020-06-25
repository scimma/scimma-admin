from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.conf import settings


@login_required
def index(request):
    creds = []
    return render(
        request, 'hopskotch_auth/index.html',
        dict(creds=creds),
    )


def login(request):
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    creds = []
    return render(
        request, 'hopskotch_auth/login.html',
        dict(creds=creds),
    )


def logout(request):
    return HttpResponse("you're logged out!")


@login_required
def create(request):
    return HttpResponse("not implemented")


@login_required
def delete(request):
    return HttpResponse("not implemented")
