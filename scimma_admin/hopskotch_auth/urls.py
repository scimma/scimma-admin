from django.urls import path

from . import views
from . import callbacks


urlpatterns = [
    path("", views.index, name="index"),
    path("login", views.login, name="login"),
    path("logout", views.logout, name="logout"),
    path("login_failure", views.login_failure, name="login_failure"),

    path("create_credential", views.create_credential, name="create_credential"),
    path("suspend_credential/<str:credname>&<str:redirect_to>", views.suspend_credential, name="suspend_credential"),
    path("create_group", views.create_group, name="create_group"),
    path("finished_group", views.finished_group, name="finished_group"),
    path("manage_credential/<str:credname>", views.manage_credential, name="manage_credential"),
    path("create_topic", views.create_topic, name="create_topic"),
    path("manage_topic/<str:topicname>", views.manage_topic, name="manage_topic"),
    path("manage_group_members/<str:groupname>", views.manage_group_members, name="manage_group_members"),
    path("manage_group_topics/<str:groupname>", views.manage_group_topics, name="manage_group_topics"),
    path("admin_credential", views.admin_credential, name="admin_credential"),
    path("admin_topic", views.admin_topic, name="admin_topic"),
    path("admin_group", views.admin_group, name="admin_group"),
    path("get_topic_permissions", views.get_topic_permissions, name="get_topic_permissions"),
    path("create_topic_in_group", views.create_topic_in_group, name="create_topic_in_group"),
    path("bulk_set_topic_permissions", callbacks.bulk_set_topic_permissions, name="bulk_set_topic_permissions"),

    path("get_available_credential_topics", callbacks.get_available_credential_topics, name="get_available_credential_topics"),
    path("bulk_set_credential_permissions", callbacks.bulk_set_credential_permissions, name="bulk_set_credential_permissions"),
    path("get_group_permissions", callbacks.get_group_permissions, name="get_group_permissions"),
    path("delete_all_credential_permissions", callbacks.delete_all_credential_permissions, name="delete_all_credential_permissions"),
    path("add_all_credential_permission", callbacks.add_all_credential_permission, name="add_all_credential_permission"),
    path("delete_credential", callbacks.delete_credential, name="delete_credential"),
    path("delete_topic", callbacks.delete_topic, name="delete_topic"),
    path("delete_group", callbacks.delete_group, name="delete_group"),
    path("toggle_suspend_credential", callbacks.toggle_suspend_credential, name="toggle_suspend_credential"),
    path("group_add_member", callbacks.group_add_member, name="group_add_member"),
    path("group_remove_member", callbacks.group_remove_member, name="group_remove_member"),
    path("user_change_status", callbacks.user_change_status, name="user_change_status"),
    path("add_group_to_topic", callbacks.add_group_to_topic, name="add_group_to_topic"),
    path("add_topic_group_permission", callbacks.add_topic_group_permission, name="add_topic_group_permission"),
    path("remove_topic_group_permission", callbacks.remove_topic_group_permission, name="remove_topic_group_permission"),
    path("download", views.download, name="download"),

]
