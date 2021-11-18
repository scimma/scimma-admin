from django.urls import path

from . import views


urlpatterns = [
    path("", views.index, name="index"),
    path("login", views.login, name="login"),
    path("logout", views.logout, name="logout"),
    path("login_failure", views.login_failure, name="login_failure"),

    path("create_credential", views.create_credential, name="create_credential"),
    path("delete_credential/<str:credname>&<str:redirect_to>", views.delete_credential, name="delete_credential"),
    path("suspend_credential/<str:credname>&<str:redirect_to>", views.suspend_credential, name="suspend_credential"),
    path("create_group", views.create_group, name="create_group"),
    path("delete_group/<str:groupname>", views.delete_group, name="delete_group"),
    path("finished_group", views.finished_group, name="finished_group"),
    path("manage_credential/<str:username>", views.manage_credential, name="manage_credential"),
    path("create_topic", views.create_topic, name="create_topic"),
    path("manage_topic/<str:topicname>", views.manage_topic, name="manage_topic"),
    path("delete_topic/<str:topicname>", views.delete_topic, name="delete_topic"),
    path("manage_group_members/<str:groupname>", views.manage_group_members, name="manage_group_members"),
    path("manage_group_topics/<str:groupname>", views.manage_group_topics, name="manage_group_topics"),
    path("admin_credential", views.admin_credential, name="admin_credential"),
    path("admin_topic", views.admin_topic, name="admin_topic"),
    path("admin_group", views.admin_group, name="admin_group"),

    path("add_credential_permission", views.add_credential_permission, name="add_credential_permission"),
    path("remove_credential_permission", views.remove_credential_permission, name="remove_credential_permission"),
    path("add_topic_group", views.add_topic_group, name="add_topic_group"),
    path("remove_topic_group", views.remove_topic_group, name="remove_topic_group"),
    path("remove_group_topic", views.remove_group_topic, name="remove_group_topic")
] 
