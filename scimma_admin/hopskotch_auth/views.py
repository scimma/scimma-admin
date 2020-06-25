from django.shortcuts import render
from django.http import HttpResponse


def index(request):
    return HttpResponse("Hello, world.")
# Create your views here.


def login(request):
    return render(request, 'hopskotch_auth/login.html')


def logout(request):
    return HttpResponse("you're logged out!")
