from django.urls import path

from . import views


urlpatterns = [
    path("", views.index, name="index"),
    path("login", views.login, name="login"),
    path("logout", views.logout, name="logout"),
    path("delete", views.delete, name="delete"),
    path("download", views.download, name="download"),
    path("create", views.create, name="create"),
    path("group_management", views.group_management, name="group_management"),
    path("create_group", views.create_group, name="create_group"),
    path("edit_group", views.edit_group, name="edit_group"),
    path("delete_group", views.delete_group, name="delete_group"),
    path("topic_management", views.topic_management, name="topic_management"),
    path("credential_management", views.credential_management, name="credential_management"),
    path("change_membership_status", views.change_membership_status, name="change_membership_status"),
    path("remove_user", views.remove_user, name="remove_user"),
    path("create_topic", views.create_topic, name="create_topic"),
    path("edit_topic", views.edit_topic, name="edit_topic"),
    path("set_topic_public_read_access",views.set_topic_public_read_access, name="set_topic_public_read_access"),
    path("delete_topic", views.delete_topic, name="delete_topic"),
    path("remove_group_permission", views.remove_group_permission, name="remove_group_permission"),
    path("add_group_permission", views.add_group_permission, name="add_group_permission"),
    path("edit_credential", views.edit_credential, name="edit_credential"),
    path("add_credential_permission", views.add_credential_permission, name="add_credential_permission"),
    path("remove_credential_permission", views.remove_credential_permission, name="remove_credential_permission"),
    path("suspend_credential", views.suspend_credential, name="suspend_credential"),
    path("unsuspend_credential", views.unsuspend_credential, name="unsuspend_credential"),
] 
