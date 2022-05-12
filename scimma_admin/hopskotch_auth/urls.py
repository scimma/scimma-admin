from django.urls import path

from . import views, api_views


urlpatterns = [
    path("", views.index, name="index"),
    path("login", views.login, name="login"),
    path("logout", views.logout, name="logout"),
    path("login_failure", views.login_failure, name="login_failure"),
    path("delete", views.delete, name="delete"),
    path("download", views.download, name="download"),
    path("create", views.create, name="create"),
    path("group_management", views.group_management, name="group_management"),
    path("create_group", views.create_group, name="create_group"),
    path("edit_group", views.edit_group, name="edit_group"),
    path("delete_group", views.delete_group, name="delete_group"),
    path("change_group_description", views.change_group_description, name="change_group_description"),
    path("topic_management", views.topic_management, name="topic_management"),
    path("credential_management", views.credential_management, name="credential_management"),
    path("change_membership_status", views.change_membership_status, name="change_membership_status"),
    path("remove_user", views.remove_user, name="remove_user"),
    path("create_topic", views.create_topic, name="create_topic"),
    path("edit_topic", views.edit_topic, name="edit_topic"),
    path("change_topic_description", views.change_topic_description, name="change_topic_description"),
    path("set_topic_public_read_access",views.set_topic_public_read_access, name="set_topic_public_read_access"),
    path("delete_topic", views.delete_topic, name="delete_topic"),
    path("remove_group_permission", views.remove_group_permission, name="remove_group_permission"),
    path("add_group_permission", views.add_group_permission, name="add_group_permission"),
    path("edit_credential", views.edit_credential, name="edit_credential"),
    path("change_credential_description", views.change_credential_description, name="change_credential_description"),
    path("add_credential_permission", views.add_credential_permission, name="add_credential_permission"),
    path("remove_credential_permission", views.remove_credential_permission, name="remove_credential_permission"),
    path("suspend_credential", views.suspend_credential, name="suspend_credential"),
    path("unsuspend_credential", views.unsuspend_credential, name="unsuspend_credential"),

    #----

    path("api/scram/first", api_views.scram_first.as_view(), name="scram_first"),
	path("api/scram/final", api_views.scram_final.as_view(), name="scram_final"),

	path("api/oidc/token_for_user", api_views.token_for_oidc_user.as_view(), name="token_for_user"),

	path("api/users", api_views.UserViewSet.as_view({"get": "list"}), name="users"),
	path("api/users/<int:pk>", api_views.UserViewSet.as_view({"get": "retrieve"}), name="user_detail"),
	path("api/users/<int:user>/credentials", api_views.SCRAMCredentialsViewSet.as_view({"get": "list"}), name="user_credentials"),
	path("api/users/<int:user>/credentials/<int:pk>", api_views.SCRAMCredentialsViewSet.as_view({"get": "retrieve", "patch": "partial_update"}), name="user_credential_detail"),
	path("api/users/<int:user>/credentials/<int:cred>/permissions", api_views.CredentialKafkaPermissionViewSet.as_view({"get": "list", "post": "create"}), name="user_credential_permissions"),
	path("api/users/<int:user>/memberships", api_views.GroupMembershipViewSet.as_view({"get": "list"}), name="user_groups"),

	path("api/scram_credentials", api_views.SCRAMCredentialsViewSet.as_view({"get": "list", "post": "create"}), name="scram_credentials"),
	path("api/scram_credentials/<int:pk>", api_views.SCRAMCredentialsViewSet.as_view({"get": "retrieve", "patch": "partial_update"}), name="scram_credentials_detail"),

	path("api/topics", api_views.KafkaTopicViewSet.as_view({"get": "list"}), name="topics"),
	path("api/topics/<int:pk>", api_views.KafkaTopicViewSet.as_view({"get": "retrieve"}), name="topic_detail"),
	path("api/topics/<int:topic>/permissions", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list"}), name="topic_permissions"),

	path("api/groups", api_views.GroupViewSet.as_view({"get": "list"}), name="groups"),
	path("api/groups/<int:pk>", api_views.GroupViewSet.as_view({"get": "retrieve"}), name="group_detail"),
	path("api/groups/<int:group>/members", api_views.GroupMembershipViewSet.as_view({"get": "list"}), name="group_members"),
	path("api/groups/<int:owning_group>/topics", api_views.KafkaTopicViewSet.as_view({"get": "list", "post": "create"}), name="group_topics"),
	path("api/groups/<int:owning_group>/topics/<int:pk>", api_views.KafkaTopicViewSet.as_view({"get": "retrieve", "delete": "destroy", "put": "partial_update", "patch": "partial_update"}), name="group_topic_detail"),
	path("api/groups/<int:granting_group>/topics/<int:topic>/permissions", api_views.KafkaTopicViewSet.as_view({"get": "list", "post": "create"}), name="group_topic_permissions"),
	path("api/groups/<int:granting_group>/topics/<int:topic>/permissions/<int:pk>", api_views.KafkaTopicViewSet.as_view({"get": "retrieve", "post": "destroy"}), name="group_topic_permission_detail"),
	path("api/groups/<int:granting_group>/permissions_given", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list"}), name="group_permissions_given"),
	path("api/groups/<int:subject_group>/permissions_received", api_views.GroupKafkaPermissionViewSet.as_view({"get": "list"}), name="group_permissions_received"),
] 
