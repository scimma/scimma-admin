from django.urls import path

from . import views


urlpatterns = [
    path("", views.index, name="index"),
    path("login", views.login, name="login"),
    path("logout", views.logout, name="logout"),
    path("delete", views.delete, name="delete"),
    path("download", views.download, name="download"),
    path("create", views.create, name="create"),
]
