from django.urls import path
from django.views.generic import TemplateView

from . import views
from . import callbacks
from . import api_views


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
    path("add_credential_permissions", callbacks.add_credential_permissions, name="add_credential_permissions"),
    path("remove_credential_permissions", callbacks.remove_credential_permissions, name="remove_credential_permissions"),
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
    path("remove_topic_from_group", callbacks.remove_topic_from_group, name="remove_topic_from_group"),
    path("subscribe_openmma", callbacks.subscribe_openmma, name="subscribe_openmma"),
    path("unsubscribe_openmma", callbacks.unsubscribe_openmma, name="unsubscribe_openmma"),
    path("download", views.download, name="download"),

    #----

    path("api/version", api_views.Version.as_view(), name="version"),

    path("api/v<int:version>/multi", api_views.MultiRequest.as_view(), name="multi"),

    path("api/v<int:version>/scram/first", api_views.ScramFirst.as_view(), name="scram_first"),
    path("api/v<int:version>/scram/final", api_views.ScramFinal.as_view(), name="scram_final"),

    path("api/v<int:version>/oidc/token_for_user", api_views.TokenForOidcUser.as_view(), name="token_for_user"),

    path("api/v<int:version>/token/issue", api_views.IssueToken.as_view(), name="issue_token"),
    path("api/v<int:version>/token/replace", api_views.ReplaceToken.as_view(), name="replace_token"),

	# v0, for backwards compatibility

	path("api/v0/users", api_views.UserViewSet.as_view({"get": "list", "post": "create"}), {"name":"users", "version":0}),
    path("api/v0/users/<int:pk>", api_views.UserViewSet.as_view({"get": "retrieve", "delete": "destroy"}), {"name":"user_detail", "version":0}),
    path("api/v0/users/<int:user>/credentials", api_views.SCRAMCredentialsViewSet.as_view({"get": "list", "post": "create"}), {"name":"user_credentials", "version":0}),
    path("api/v0/users/<int:user>/credentials/<int:pk>", api_views.SCRAMCredentialsViewSet.as_view({"get": "retrieve", "patch": "partial_update", "delete": "destroy"}), {"name":"user_credential_detail", "version":0}),
    path("api/v0/users/<int:user>/credentials/<int:pk>/permissions", api_views.CredentialKafkaPermissionViewSet.as_view({"get": "list", "post": "create"}), {"name":"user_credential_permissions", "version":0}),
    path("api/v0/users/<int:user>/memberships", api_views.GroupMembershipViewSet.as_view({"get": "list"}), {"name":"user_groups", "version":0}),

    path("api/v0/scram_credentials", api_views.SCRAMCredentialsViewSet.as_view({"get": "list", "post": "create"}), {"name":"scram_credentials", "version":0}),
    path("api/v0/scram_credentials/<int:pk>", api_views.SCRAMCredentialsViewSet.as_view({"get": "retrieve", "patch": "partial_update"}), {"name":"scram_credentials_detail", "version":0}),

    path("api/v0/topics", api_views.KafkaTopicViewSet.as_view({"get": "list"}), {"name":"topics", "version":0}),
    path("api/v0/topics/<int:pk>", api_views.KafkaTopicViewSet.as_view({"get": "retrieve", "delete": "destroy"}), {"name":"topic_detail", "version":0}),
    path("api/v0/topics/<int:topic>/permissions", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list"}), {"name":"topic_permissions", "version":0}),

    path("api/v0/groups", api_views.GroupViewSet.as_view({"get": "list", "post": "create"}), {"name":"groups", "version":0}),
    path("api/v0/groups/<int:pk>", api_views.GroupViewSet.as_view({"get": "retrieve", "patch": "partial_update", "delete": "destroy"}), {"name":"group_detail", "version":0}),
    path("api/v0/groups/<int:group>/members", api_views.GroupMembershipViewSet.as_view({"get": "list", "post": "create"}), {"name":"group_members", "version":0}),
    path("api/v0/groups/<int:group>/members/<int:pk>", api_views.GroupMembershipViewSet.as_view({"get": "retrieve", "patch": "partial_update", "delete": "destroy"}), {"name":"group_member_detail", "version":0}),
    path("api/v0/groups/<int:owning_group>/topics", api_views.KafkaTopicViewSet.as_view({"get": "list", "post": "create"}), {"name":"group_topics", "version":0}),
    path("api/v0/groups/<int:owning_group>/topics/<int:pk>", api_views.KafkaTopicViewSet.as_view({"get": "retrieve", "delete": "destroy", "patch": "partial_update"}), {"name":"group_topic_detail", "version":0}),
    path("api/v0/groups/<int:granting_group>/topics/<int:topic>/permissions", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list", "post": "create"}), {"name":"group_topic_permissions", "version":0}),
    path("api/v0/groups/<int:granting_group>/topics/<int:topic>/permissions/<int:pk>", api_views.GroupKafkaPermissionViewSet.as_view({"get": "retrieve", "delete": "destroy"}), {"name":"group_topic_permission_detail", "version":0}),
    path("api/v0/groups/<int:granting_group>/permissions_given", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list"}), {"name":"group_permissions_given", "version":0}),
    path("api/v0/groups/<int:granting_group>/permissions_given/<int:pk>", api_views.GroupKafkaPermissionViewSet.as_view({"get": "retrieve", "delete": "destroy"}), {"name":"group_permissions_given_detail", "version":0}),
    path("api/v0/groups/<int:subject_group>/permissions_received", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list"}), {"name":"group_permissions_received", "version":0}),

    # Current version

    path("api/v<int:version>/users", api_views.UserViewSet.as_view({"get": "list", "post": "create"}), name="users"),
    path("api/v<int:version>/users/<str:username>", api_views.UserViewSet.as_view({"get": "retrieve", "delete": "destroy"}), name="user_detail"),
    path("api/v<int:version>/users/<str:user>/credentials", api_views.SCRAMCredentialsViewSet.as_view({"get": "list", "post": "create"}), name="user_credentials"),
    path("api/v<int:version>/users/<str:user>/credentials/<str:username>", api_views.SCRAMCredentialsViewSet.as_view({"get": "retrieve", "patch": "partial_update", "delete": "destroy"}), name="user_credential_detail"),
    path("api/v<int:version>/users/<str:user>/credentials/<str:cred>/permissions", api_views.CredentialKafkaPermissionViewSet.as_view({"get": "list", "post": "create"}), name="user_credential_permissions"),
    path("api/v<int:version>/users/<str:user>/memberships", api_views.GroupMembershipViewSet.as_view({"get": "list"}), name="user_groups"),

    path("api/v<int:version>/current_user", api_views.UserViewSet.as_view({"get": "retrieve_current"}), name="current_user"),
    path("api/v<int:version>/current_user/credentials", api_views.SCRAMCredentialsViewSet.as_view({"get": "list_for_current_user"}), name="current_user_credentials"),
    path("api/v<int:version>/current_user/memberships", api_views.GroupMembershipViewSet.as_view({"get": "list_for_current_user"}), name="current_user_groups"),

    path("api/v<int:version>/scram_credentials", api_views.SCRAMCredentialsViewSet.as_view({"get": "list", "post": "create"}), name="scram_credentials"),
    path("api/v<int:version>/scram_credentials/<str:username>", api_views.SCRAMCredentialsViewSet.as_view({"get": "retrieve", "patch": "partial_update"}), name="scram_credentials_detail"),
    path("api/v<int:version>/scram_credentials/<str:cred>/permissions", api_views.CredentialKafkaPermissionViewSet.as_view({"get": "list", "post": "create"}), name="scram_credential_permissions"),
	path("api/v<int:version>/scram_credentials/<str:cred>/permissions/topic/<str:topic>", api_views.CredentialPermissionsForTopic.as_view(), name="scram_credential_topic_permissions"),

    path("api/v<int:version>/current_credential", api_views.SCRAMCredentialsViewSet.as_view({"get": "retrieve_current"}), name="current_credential"),
    path("api/v<int:version>/current_credential/permissions", api_views.CredentialKafkaPermissionViewSet.as_view({"get": "list_for_current_credential"}), name="current_credential_permissions"),
    path("api/v<int:version>/current_credential/permissions/topic/<str:topic>", api_views.CurrentCredentialPermissionsForTopic.as_view(), name="current_credential_topic_permissions"),

    path("api/v<int:version>/topics", api_views.KafkaTopicViewSet.as_view({"get": "list"}), name="topics"),
    path("api/v<int:version>/topics/<str:name>", api_views.KafkaTopicViewSet.as_view({"get": "retrieve", "delete": "destroy", "patch": "partial_update"}), name="topic_detail"),
    path("api/v<int:version>/topics/<str:topic>/permissions", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list", "post": "create"}), name="topic_permissions"),
    path("api/v<int:version>/topics/<str:topic>/permissions/<int:pk>", api_views.GroupKafkaPermissionViewSet.as_view({"get": "retrieve", "delete": "destroy"}), name="topic_permission_detail"),

    path("api/v<int:version>/groups", api_views.GroupViewSet.as_view({"get": "list", "post": "create"}), name="groups"),
    path("api/v<int:version>/groups/<str:name>", api_views.GroupViewSet.as_view({"get": "retrieve", "patch": "partial_update", "delete": "destroy"}), name="group_detail"),
    path("api/v<int:version>/groups/<str:group>/members", api_views.GroupMembershipViewSet.as_view({"get": "list", "post": "create"}), name="group_members"),
    path("api/v<int:version>/groups/<str:group>/members/<int:pk>", api_views.GroupMembershipViewSet.as_view({"get": "retrieve", "patch": "partial_update", "delete": "destroy"}), name="group_member_detail"),
    path("api/v<int:version>/groups/<str:owning_group>/topics", api_views.KafkaTopicViewSet.as_view({"get": "list", "post": "create"}), name="group_topics"),
    path("api/v<int:version>/groups/<str:owning_group>/topics/<str:name>", api_views.KafkaTopicViewSet.as_view({"get": "retrieve", "delete": "destroy", "patch": "partial_update"}), name="group_topic_detail"),
    path("api/v<int:version>/groups/<str:granting_group>/topics/<str:topic>/permissions", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list", "post": "create"}), name="group_topic_permissions"),
    path("api/v<int:version>/groups/<str:granting_group>/topics/<str:topic>/permissions/<int:pk>", api_views.GroupKafkaPermissionViewSet.as_view({"get": "retrieve", "delete": "destroy"}), name="group_topic_permission_detail"),
    path("api/v<int:version>/groups/<str:granting_group>/permissions_given", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list"}), name="group_permissions_given"),
    path("api/v<int:version>/groups/<str:granting_group>/permissions_given/<int:pk>", api_views.GroupKafkaPermissionViewSet.as_view({"get": "retrieve", "delete": "destroy"}), name="group_permissions_given_detail"),
    path("api/v<int:version>/groups/<str:subject_group>/permissions_received", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list"}), name="group_permissions_received"),

    path('api/swagger-ui/', TemplateView.as_view(
         template_name='hopskotch_auth/swagger-ui.html',
         extra_context={'schema_url':'openapi-schema'}
    ), name='swagger-ui'),
]
