from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.db import transaction
from django.views.decorators.http import require_POST
from django.urls import reverse
from wsgiref.util import FileWrapper
from io import StringIO

from .models import *

from mozilla_django_oidc.auth import get_user_model

import logging

logger = logging.getLogger(__name__)


def redirect_with_error(request, operation, reason, redirect_to):
    logger.info(f"Ignored request by user {request.user.username} ({request.user.email}. "
                f"Operation={operation}, Reason={reason}")
    messages.error(request, reason)
    return redirect(redirect_to)


@login_required
def index(request):
    credentials = list(request.user.scramcredentials_set.all())
    credentials.sort(key=lambda cred: cred.created_at)
    memberships = []
    for membership in request.user.groupmembership_set.all().select_related('group'):
        memberships.append({"group_id":membership.group.id,
                            "group_name":membership.group.name,
                            "status":membership.status})
    memberships.sort(key=lambda m: m["group_name"])
    accessible_topics = []
    for name, desc in topics_accessible_to_user(request.user).items():
        accessible_topics.append({"name":name,
                           "access_type":desc})
    accessible_topics.sort(key=lambda t: t["name"])
    return render(
        request, 'hopskotch_auth/index.html',
        dict(credentials=credentials, memberships=memberships,
             accessible_topics=accessible_topics),
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
    logger.info(f"User {request.user.username} ({request.user.email}) requested "
                f"to create a new credential from {request.META['REMOTE_ADDR']}")
    bundle = new_credentials(request.user)
    logger.info(f"Created new credential {bundle.username} on behalf of user "
                f"{request.user.username} ({request.user.email})")
    return render(
        request, 'hopskotch_auth/create.html',
        dict(username=bundle.username, password=bundle.password),
    )


@login_required
def delete(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to delete credential "
                f"{request.GET.get('cred_username','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    cred_username = request.GET.get('cred_username')
    if cred_username is None:
        return redirect_with_error(request, "Delete a credential", 
                                   "Missing cred_username parameter in delete request", 
                                   "index")

    try:
        delete_credentials(request.user, cred_username)
    except ObjectDoesNotExist:
        return redirect_with_error(request, f"Delete credential {cred_username}", 
                                   "User does not own that credential", "index")
    except MultipleObjectsReturned:
        return redirect_with_error(request, f"Delete credential {cred_username}", 
                                   "Multiple credentials found with that username", 
                                   "index")

    logger.info(f"deleted creds associated with username: {cred_username}")
    messages.info(request, f"Deleted credentials with username {cred_username}.")

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
    logger.info(f"Sent data for credential {request.POST['username']} to user "
                f"{request.user.username} ({request.user.email}) at {request.META['REMOTE_ADDR']}")
    return response


@login_required
def group_management(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested "
                f"the group management page from {request.META['REMOTE_ADDR']}")
    
    # only staff can manage groups
    if not request.user.is_staff:
        return redirect_with_error(request, "access the group management page", 
                                   "User is not a staff member.", "index")
    groups=list(Group.objects.all())
    groups.sort(key=lambda g: g.name)
    return render(request, 'hopskotch_auth/group_management.html',
                  dict(groups=groups))


@require_POST
@login_required
def create_group(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to create a group with name "
                f"{request.POST.get('name','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    # only staff can create new groups
    if not request.user.is_staff:
        return redirect_with_error(request, "Create a group", 
                                   "User is not a staff member.", "index")
    
    if not "name" in request.POST or len(request.POST["name"])==0:
        return redirect_with_error(request, "Create a group", 
                                   "Missing or invalid group name", "create_group")
    
    group_name = request.POST["name"]
    # make sure that the group name is not already in use
    if Group.objects.filter(name=group_name).exists():
        return redirect_with_error(request, f"Create a group named {group_name}", 
                                   "Group name already in use.", "create_group")
    
    # no collision, so proceed with creating the group
    group = Group.objects.create(name=group_name)

    logger.info(f"Created group {group_name} with ID {group.id}")
    messages.info(request, "Created group \""+group_name+'"')
    base_edit_url = reverse("edit_group")
    return redirect(base_edit_url+"?group_id="+str(group.id))


@login_required
def edit_group(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to edit group ID "
                f"{request.GET.get('group_id','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    if not "group_id" in request.GET or len(request.GET["group_id"])==0:
        return redirect_with_error(request, "Edit a group", 
                                   "Missing or invalid group ID", "index")
    
    group_id = request.GET["group_id"]
    
    # only group owners and staff can edit groups
    if not is_group_owner(request.user,group_id) and not request.user.is_staff:
        return redirect_with_error(request, f"Edit the group with ID {group_id}", 
                                   "User is not a group owner or staff member", "index")

    try:
        group = Group.objects.get(id=group_id)
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, f"Edit the group with ID {group_id}", 
                                   "No such group exists", "index")

    memberships = []
    for member in group.members.all():
        membership = member.groupmembership_set.get(group=group)
        memberships.append({"user_id":member.id,"user_name":member.username,"user_email":member.email,"status":membership.status})
    memberships.sort(key=lambda m: m["user_email"])
    
    all_users = list(get_user_model().objects.all().values("id","username","email"))
    all_users.sort(key=lambda u: u["email"])

    topics=list(KafkaTopic.objects.filter(owning_group=group_id))
    topics.sort(key=lambda t: t.name)

    return render(
        request, "hopskotch_auth/edit_group.html",
        dict(group=group, memberships=memberships, all_users=all_users, 
             topics=topics)
    )


@require_POST
@login_required
def delete_group(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to delete group ID "
                f"{request.POST.get('group_id','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    # only staff can delete groups
    if not request.user.is_staff:
        return redirect_with_error(request, f"Delete the group with ID {group.id}", 
                                   "User is not a staff member", "index")
    
    if not "group_id" in request.POST or len(request.POST["group_id"])==0:
        return redirect_with_error(request, "Delete a group", 
                                   "Missing or invalid group ID", "group_management")
    
    try:
        with transaction.atomic():
            group = Group.objects.get(id=request.POST["group_id"])
            # clean up any permissions that users had by being in the group
            for member in group.members.all():
                remove_user_group_permissions(member.id, group.id)
            group_name = group.name
            group.delete()
            logger.info(f"Deleted group {group_name} with ID {group.id}")
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, f"Delete the group with ID {group.id}", 
                                   "No such group exists", "group_management")
    
    messages.info(request, "Group "+group_name+" deleted")
    return redirect("group_management")


@login_required
def topic_management(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested "
                f"the global topic management page from {request.META['REMOTE_ADDR']}")

    # only staff can manage all topics
    if not request.user.is_staff:
        return redirect_with_error(request, "Access the topic management page",
                                   "User is not a staff member", "index")
    topics=list(KafkaTopic.objects.all().select_related("owning_group"))
    topics.sort(key=lambda topic: topic.name)
    topics.sort(key=lambda topic: topic.owning_group.name)
    return render(
        request, 'hopskotch_auth/topic_management.html',
        dict(topics=topics)
    )


@login_required
def credential_management(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested "
                f"the global credential management page from {request.META['REMOTE_ADDR']}")
    
    # only staff can manage others' credentials
    if not request.user.is_staff:
        return redirect_with_error(request, "Access the credential management page", 
                                   "User is not a staff member", "index")
    credentials=list(SCRAMCredentials.objects.all().select_related("owner"))
    credentials.sort(key=lambda cred: cred.username)
    credentials.sort(key=lambda cred: cred.owner.username)
    return render(
        request, 'hopskotch_auth/credential_management.html',
        dict(credentials=credentials)
    )


# Also used to add group members
@require_POST
@login_required
def change_membership_status(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to change user ID "
                f"{request.POST.get('user_id','<unset>')}'s status in group ID "
                f"{request.POST.get('group_id','<unset>')} to {request.POST.get('status','<unset>')}"
                f" from {request.META['REMOTE_ADDR']}")
    
    if not "group_id" in request.POST or len(request.POST["group_id"])==0:
        return redirect_with_error(request, "Change a user's group membership status", 
                                   "Missing or invalid group ID", "index")
    if not "user_id" in request.POST or len(request.POST["user_id"])==0:
        return redirect_with_error(request, "Change a user's group membership status", 
                                   "Missing or invalid user ID", "index")
    if not "status" in request.POST or len(request.POST["status"])==0 \
      or not request.POST["status"] in MembershipStatus.__members__:
        return redirect_with_error(request, "Change a user's group membership status", 
                                   "Missing or invalid membership status", "index")
    
    group_id = request.POST["group_id"]
    user_id=request.POST["user_id"]
    status=request.POST["status"]
    
    # only group owners and staff can add users to groups/change membership status
    if not is_group_owner(request.user,group_id) and not request.user.is_staff:
        return redirect_with_error(request, 
                                   f"Change a user's group membership status in the group with ID {group_id}", 
                                   "Requester is not a group owner or staff member", 
                                   "index")
    
    try:
        group = Group.objects.get(id=group_id)
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, 
                                   f"Change a user's group membership status in the group with ID {group_id}", 
                                   "No such group exists", "index")

    try:
        target_user = get_user_model().objects.get(id=user_id)
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, 
                                   f"Change a user's group membership status in the group with ID {group_id}", 
                                   "Target user does not exist", "index")

    try:
        membership = GroupMembership.objects.get(user_id=user_id, group_id=group_id)
        membership.status = MembershipStatus[status]
        membership.save()
        logger.info(f"Changed user {target_user.username} ({target_user.email}) status in group {group.name} to {status}")
        messages.info(request, "Changed user membership status.")
    except ObjectDoesNotExist as dne:
        # membership does not exist; create it
        GroupMembership.objects.create(user_id=user_id, group_id=group_id, status=MembershipStatus[status])
        logger.info(f"Made user {target_user.username} ({target_user.email}) a member of group {group.name} with status {status}")
        messages.info(request, "Added user to group.")
    
    base_edit_url = reverse("edit_group")
    return redirect(base_edit_url+"?group_id="+group_id)


@require_POST
@login_required
def remove_user(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to remove user ID "
                f"{request.POST.get('user_id','<unset>')} from group ID "
                f"{request.POST.get('group_id','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    if not "group_id" in request.POST or len(request.POST["group_id"])==0:
        return redirect_with_error(request, "Remove a user from a group", 
                                   "Missing or invalid group ID", "index")
    if not "user_id" in request.POST or len(request.POST["user_id"])==0:
        return redirect_with_error(request, "Remove a user from a group", 
                                   "Missing or invalid user ID", "index")
    
    group_id = request.POST["group_id"]
    user_id=request.POST["user_id"]
    
    # only group owners and staff can remove users from groups
    if not is_group_owner(request.user,group_id) and not request.user.is_staff:
        return redirect_with_error(request, 
                                   f"Remove a user from the group with ID {group_id}", 
                                   "Requester is not a group owner or staff member", 
                                   "index")
    
    try:
        group = Group.objects.get(id=group_id)
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, 
                                   f"Remove a user from the group with ID {group_id}", 
                                   "No such group exists", "index")

    try:
        target_user = get_user_model().objects.get(id=user_id)
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, 
                                   f"Remove the user with id {user_id} from the group with ID {group_id}", 
                                   "No such user exists", "index")

    try:
        with transaction.atomic():
            membership = GroupMembership.objects.get(user_id=user_id, group_id=group_id)
            remove_user_group_permissions(user_id, group_id)
            membership.delete()
    except ObjectDoesNotExist as dne:
        # apparently we need do nothing
        pass

    logger.info(f"Removed user {target_user.username} ({target_user.email}) from"
                f" group {group.name}")
    messages.info(request, "Removed user from group.")
    base_edit_url = reverse("edit_group")
    return redirect(base_edit_url+"?group_id="+group_id)


@require_POST
@login_required
def create_topic(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to create a topic with name "
                f"{request.POST.get('topic_name','<unset>')} owned by group ID "
                f"{request.POST.get('group_id','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    if not "group_id" in request.POST:
        return redirect_with_error(request, "Create a topic", 
                                   "Missing or invalid owning group ID", "index")
    
    group_id = request.POST["group_id"]

    # make sure that the requestor has the authority to do this
    if not is_group_owner(request.user, group_id) and not request.user.is_staff:
        return redirect_with_error(request, 
                                   f"Create a topic owned by the group with ID {group_id}", 
                                   "Requester is not a group owner or staff member", 
                                   "index")
    # if the requesting user is a member of the proposed owning group it also proves that the 
    # group exists, so we don't need to check that separately

    if not "topic_name" in request.POST or not validate_topic_name(request.POST["topic_name"]):
        return redirect_with_error(request, "Create a topic", 
                                   "Missing or invalid topic name", 
                                   reverse("edit_group")+"?group_id="+group_id)
    
    topic_name = request.POST["topic_name"]

    # make sure that the topic name is not already in use
    if KafkaTopic.objects.filter(name=topic_name).exists():
        return redirect_with_error(request, "Create a topic", 
                                   "Topic name already in use", 
                                   reverse("edit_group")+"?group_id="+group_id)

    group = Group.objects.get(id=group_id)
    
    with transaction.atomic():
        topic = KafkaTopic.objects.create(name=topic_name, owning_group=group)
        # assign complete access to the owning group
        GroupKafkaPermission.objects.create(principal=group, topic=topic, operation=KafkaOperation.All)

    logger.info(f"Created topic {topic_name} owned by group {group.name}")
    messages.info(request, "Created topic \""+topic_name+'"')
    base_edit_url = reverse("edit_topic")
    return redirect(base_edit_url+"?topic_id="+str(topic.id))


@login_required
def edit_topic(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to edit topic ID "
                f"{request.GET.get('topic_id','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    if not "topic_id" in request.GET:
        return redirect_with_error(request, "Edit a topic", 
                                   "Missing or invalid topic ID", "index")
    
    try:
        topic = KafkaTopic.objects.get(id=request.GET["topic_id"])
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Edit a topic", "No such topic", "index")

    owning_group = topic.owning_group
    # only group owners and staff may use this page 
    if not is_group_owner(request.user, owning_group.id) and not request.user.is_staff:
        return redirect_with_error(request, 
                                   f"Create a topic owned by the group with ID {owning_group.id}", 
                                   "Requester is not a group owner or staff member", 
                                   "index")

    permissions = []
    for perm in topic.groupkafkapermission_set.all().select_related("principal"):
        permissions.append({"group_name":perm.principal.name, "group_id":perm.principal.id, 
                           "operation":perm.operation, "id":perm.id})
    permissions.sort(key=lambda p: p["operation"])
    permissions.sort(key=lambda p: p["group_name"])

    all_groups = list(Group.objects.all())
    all_groups.sort(key=lambda g: g.name)
    operations = KafkaOperation.__members__.keys()

    return render(
        request, "hopskotch_auth/edit_topic.html",
        dict(topic=topic, owning_group=owning_group, permissions=permissions, 
             all_groups=all_groups, operations=operations)
        )


@require_POST
@login_required
def set_topic_public_read_access(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to set topic ID "
                f"{request.POST.get('topic_id','<unset>')} public read access to "
                f"{request.POST.get('public','<unset>')} from {request.META['REMOTE_ADDR']}")

    if not "topic_id" in request.POST:
        return redirect_with_error(request, "Set public access to a topic", 
                                   "Missing or invalid topic ID", "index")
    if not "public" in request.POST:
        return redirect_with_error(request, "Set public access to a topic", 
                                   "Missing public status to set", "index")

    try:
        topic = KafkaTopic.objects.get(id=request.POST["topic_id"])
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Set public access to a topic", 
                                   "No such topic", "index")

    owning_group = topic.owning_group
    # only group owners and staff make a topic (not) publicly readable 
    if not is_group_owner(request.user, owning_group.id) and not request.user.is_staff:
        return redirect_with_error(request, 
                                   f"Edit a topic owned by the group with ID {owning_group.id}", 
                                   "Requester is not a group owner or staff member", 
                                   "index")
    
    topic.publicly_readable = request.POST["public"].lower()=='true'
    topic.save()

    message="Made topic "+topic.name
    if topic.publicly_readable:
        message += " publicly readable"
    else:
        message += " not publicly readable"
    logger.info(message)
    messages.info(request, message)
    base_edit_url = reverse("edit_topic")
    return redirect(base_edit_url+"?topic_id="+str(topic.id))


@require_POST
@login_required
def delete_topic(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to delete topic ID "
                f"{request.POST.get('topic_id','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    if not "topic_id" in request.POST:
        return redirect_with_error(request, "Delete a topic", 
                                   "Missing or invalid topic ID", "index")
    
    try:
        topic = KafkaTopic.objects.get(id=request.POST["topic_id"])
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Delete a topic", "No such topic", "index")
    
    # make sure that the requestor has the authority to do this
    if not is_group_owner(request.user, topic.owning_group) and not request.user.is_staff:
        return redirect_with_error(request, 
                                   f"Delete a topic owned by the group {topic.owning_group}", 
                                   "Requester is not a group owner or staff member", 
                                   "index")
    
    topic_name = topic.name
    with transaction.atomic():
        delete_topic_permissions(topic.id)
        topic.delete()
    logger.info(f"Deleted topic {topic_name}")
    messages.info(request, "Deleted topic \""+topic_name+'"')
    return redirect("index")


@require_POST
@login_required
def add_group_permission(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to grant group ID "
                f"{request.POST.get('group_id','<unset>')} "
                f"{request.POST.get('operation','<unset>')} permission for topic ID "
                f"{request.POST.get('topic_id','<unset>')} from {request.META['REMOTE_ADDR']}")
                
    if not "topic_id" in request.POST:
        return redirect_with_error(request, "Grant a group permission to access a topic", 
                                   "Missing or invalid topic ID", "index")
    if not "group_id" in request.POST:
        return redirect_with_error(request, "Grant a group permission to access a topic", 
                                   "Missing or invalid group ID", "index")
    if not "operation" in request.POST:
        return redirect_with_error(request, "Grant a group permission to access a topic", 
                                   "Missing operation", "index")

    topic_id = request.POST["topic_id"]
    group_id = request.POST["group_id"]
    try:
        operation = KafkaOperation[request.POST["operation"]]
    except KeyError as ke:
        return redirect_with_error(request, "Grant a group permission to access a topic", 
                                   "Invalid operation", "index")
    
    # make sure the target topic exists
    try:
        topic = KafkaTopic.objects.get(id=topic_id)
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Grant a group permission to access a topic", 
                                   "Invalid topic ID", "index")

    # make sure that the requestor has the authority to do this
    if not is_group_owner(request.user.id, topic.owning_group) and not request.user.is_staff:
        return redirect_with_error(request, 
                                   f"Grant a group permission to access a topic owned by the group {topic.owning_group}", 
                                   "Requester is not a group owner or staff member", 
                                   "index")
    # if the requesting user is a member of the proposed owning group it also proves that the 
    # group exists, so we don't need to check that separately

    add_kafka_permission_for_group(group_id, topic, operation)
    
    logger.info(f"Granted group ID {group_id} {operation.name} permission to topic {topic.name}")
    messages.info(request, "Granted "+operation.name+" permission to topic \""+topic.name+'"')
    base_edit_url = reverse("edit_topic")
    return redirect(base_edit_url+"?topic_id="+topic_id)


@require_POST
@login_required
def remove_group_permission(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to revoke group permission with ID "
                f"{request.POST.get('perm_id','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    if not "perm_id" in request.POST:
        return redirect_with_error(request, "Revoke a group's permission to access a topic", 
                                   "Missing permission ID", "index")
    
    try:
        permission = GroupKafkaPermission.objects.get(id=request.POST["perm_id"])
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Revoke a group's permission to access a topic", 
                                   "Invalid permission ID", "index")

    topic = permission.topic
    owning_group = topic.owning_group

    # make sure that the requestor has the authority to do this
    if not is_group_owner(request.user, owning_group) and not request.user.is_staff:
        return redirect_with_error(request, 
                                   f"Revoke a group's permission to access a topic owned by the group {topic.owning_group}", 
                                   "Requester is not a group owner or staff member", 
                                   "index")

    if remove_kafka_permission_for_group(permission, owning_group):
        logger.info(f"Revoked group ID {permission.principal} {permission.operation} permission to topic {topic.name}")
        messages.info(request, "Revoked "+permission.operation.name+" permission for topic \""+topic.name+'"')
    else:
        logger.info(f"Did not revoke group ID {permission.principal} {permission.operation} permission to topic {topic.name}")
        messages.info(request, "Did not revoke "+permission.operation.name+" permission for topic \""+topic.name+'"')
    base_edit_url = reverse("edit_topic")
    return redirect(base_edit_url+"?topic_id="+str(topic.id))


@login_required
def edit_credential(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to edit permissions for credential "
                f"{request.GET.get('cred_username','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    if not "cred_username" in request.GET:
        return redirect_with_error(request, "Edit a credential", 
                                   "Missing credential name", "index")
    
    try:
        credential = SCRAMCredentials.objects.get(username=request.GET["cred_username"])
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Edit a credential", 
                                   "No such credential exists", "index")

    owner = credential.owner
    # only credential owners and staff may use this page 
    if request.user!=owner and not request.user.is_staff:
        return redirect_with_error(request, "Edit a credential", 
                                   "Requester is not the credential owner or a staff member", 
                                   "index")

    permissions = []
    for perm in credential.credentialkafkapermission_set.all().select_related('topic'):
        permissions.append({"topic_name":perm.topic.name, "operation":perm.operation, "id":perm.id})
    permissions.sort(key=lambda p: p["operation"])
    permissions.sort(key=lambda p: p["topic_name"])

    possible_perms = []
    for perm in all_permissions_for_user(owner):
        possible_perms.append({"topic":perm[2],"operation":perm[3],"desc":encode_cred_permission(perm[0],perm[1],perm[3])})

    return render(
        request, "hopskotch_auth/edit_credential.html",
        dict(cred=credential, permissions=permissions, possible_perms=possible_perms)
        )


@require_POST
@login_required
def add_credential_permission(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to add a permission "
                f"{request.POST.get('perm','<unset>')} to credential "
                f"{request.POST.get('cred_username','<unset>')} from {request.META['REMOTE_ADDR']}")
    
    if not "cred_username" in request.POST:
        return redirect_with_error(request, "Add a permission to a credential", 
                                   "Missing credential name", "index")
    if "perm" not in request.POST:
        return redirect_with_error(request, "Add a permission to a credential", 
                                   "Missing permission description", "index")
    
    try:
        credential = SCRAMCredentials.objects.get(username=request.POST["cred_username"])
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Add a permission to a credential", 
                                   "No such credential exists", "index")
    
    try:
        parent_id, _, operation = decode_cred_permission(request.POST["perm"])
    except ValueError as ve:
        return redirect_with_error(request, "Add a permission to a credential", 
                                   "Specified permission was malformed", "index")

    # make sure the requesting user actually has the rights to add this permission to this credential
    # the user must be the credential owner or a staff member
    if request.user!=credential.owner and not request.user.is_staff:
        return redirect_with_error(request, "Add a permission to a credential", 
                                   "Requester is not the credential owner or a staff member", 
                                   "index")

    # the referenced parent (group) permission must exist and 
    # the user must belong to the group with which it is associated
    try:
        parent_perm = GroupKafkaPermission.objects.get(id=parent_id)
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Add a permission to a credential", 
                                   "Referenced parent permission does not exist", 
                                   "index")
    if not is_group_member(credential.owner, parent_perm.principal):
        return redirect_with_error(request, "Add a permission to a credential", 
                                   "Requester does not have access to use the referenced parent permission", 
                                   "index")

    # the referenced group permission must actually grant the permission being requested
    if parent_perm.operation!=operation and parent_perm.operation!=KafkaOperation.All:
        return redirect_with_error(request, "Add a permission to a credential", 
                                   "Referenced parent permission does not grant the specified operation", 
                                   "index")

    if CredentialKafkaPermission.objects.filter(principal=credential, topic=parent_perm.topic, operation=operation).exists():
        # if the permission already exists, we should not add it
        # note that we don't care whether parent prmission is an exact match
        messages.info(request, str(operation)+" permission for topic "+parent_perm.topic.name+" was already present")
    else:
        CredentialKafkaPermission.objects.create(principal=credential, parent=parent_perm, topic=parent_perm.topic, operation=operation)
        logger.info(f"Added {str(operation)} permission for topic {parent_perm.topic.name} to credential {credential.username}")
        messages.info(request, f"Added {str(operation)} permission for topic {parent_perm.topic.name}")

    base_edit_url = reverse("edit_credential")
    return redirect(base_edit_url+"?cred_username="+credential.username)


@require_POST
@login_required
def remove_credential_permission(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to remove a permission ID "
                f"{request.POST.get('perm_id','<unset>')} from a credential from {request.META['REMOTE_ADDR']}")
    
    if "perm_id" not in request.POST:
        return redirect_with_error(request, "Remove a permission from a credential", 
                                   "Missing permission ID", "index")
    
    try:
        perm = CredentialKafkaPermission.objects.get(id=request.POST["perm_id"])
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Remove a permission from a credential", 
                                   "No such permission exists", "index")

    # the user must be the credential owner or a staff member
    if request.user!=perm.principal.owner and not request.user.is_staff:
        return redirect_with_error(request, "Remove a permission from a credential", 
                                   "Requester is not the credential owner or a staff member", 
                                   "index")
    
    perm.delete()

    logger.info(f"Removed {str(perm.operation)} permission for topic {perm.topic.name} from credential {perm.principal.username}")
    messages.info(request, f"Removed {str(perm.operation)} permission for topic {perm.topic.name}")
    base_edit_url = reverse("edit_credential")
    return redirect(base_edit_url+"?cred_username="+perm.principal.username)


@require_POST
@login_required
def suspend_credential(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to suspend the credential with ID "
                f"{request.POST.get('cred_id','<unset>')} from {request.META['REMOTE_ADDR']}")

    # only staff can suspend credentials
    if not request.user.is_staff:
        return redirect_with_error(request, "Suspend a credential", 
                                   "Requester is not a staff member", 
                                   "index")

    if "cred_id" not in request.POST:
        return redirect_with_error(request, "Suspend a credential", 
                                   "Missing credential ID", "index")

    try:
        cred = SCRAMCredentials.objects.get(id=request.POST["cred_id"])
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Suspend a credential", 
                                   "No such credential exists", "index")

    if not cred.suspended: 
        cred.suspended = True
        cred.save()
        logger.info(f"Suspended credential {cred.username}")
        messages.info(request, f"Suspended credential {cred.username}")

    base_edit_url = reverse("edit_credential")
    return redirect(base_edit_url+"?cred_username="+cred.username)


@require_POST
@login_required
def unsuspend_credential(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to un-suspend the credential with ID "
                f"{request.POST.get('cred_id','<unset>')} from {request.META['REMOTE_ADDR']}")

    # only staff can unsuspend credentials
    if not request.user.is_staff:
        return redirect_with_error(request, "Un-suspend a credential", 
                                   "Requester is not a staff member", 
                                   "index")

    if "cred_id" not in request.POST:
        return redirect_with_error(request, "Un-suspend a credential", 
                                   "Missing credential ID", "index")

    try:
        cred = SCRAMCredentials.objects.get(id=request.POST["cred_id"])
    except ObjectDoesNotExist as dne:
        return redirect_with_error(request, "Suspend a credential", 
                                   "No such credential exists", "index")

    if cred.suspended:
        cred.suspended = False
        cred.save()
        logger.info(f"Un-suspended credential {cred.username}")
        messages.info(request, f"Un-suspended credential {cred.username}")

    base_edit_url = reverse("edit_credential")
    return redirect(base_edit_url+"?cred_username="+cred.username)
