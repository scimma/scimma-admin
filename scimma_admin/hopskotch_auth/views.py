from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.views.decorators.http import require_POST
from django.urls import reverse
from wsgiref.util import FileWrapper
from io import StringIO

from .models import *

from mozilla_django_oidc.auth import get_user_model

import logging

logger = logging.getLogger(__name__)


@login_required
def index(request):
    credentials = request.user.scramcredentials_set.all()
    memberships = []
    for membership in request.user.groupmembership_set.all().select_related('group'):
        memberships.append({"group_id":membership.group.id,
                            "group_name":membership.group.name,
                            "status":membership.status})
    return render(
        request, 'hopskotch_auth/index.html',
        dict(credentials=credentials, memberships=memberships),
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
    logger.info(f"User {request.user.username} ({request.user.email}) requested to create a new credential from "+request.META["REMOTE_ADDR"])
    bundle = new_credentials(request.user)
    logger.info(f"Created new credential {bundle.username} on behalf of user {request.user.username} ({request.user.email})")
    return render(
        request, 'hopskotch_auth/create.html',
        dict(username=bundle.username, password=bundle.password),
    )


@login_required
def delete(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to delete credential " \
                +request.GET.get("cred_username","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    cred_username = request.GET.get('cred_username')
    if cred_username is None:
        logger.error(f"missing cred_username parameter in delete request")
        messages.error(request, "missing cred_username parameter in delete request")
        return redirect("index")

    try:
        delete_credentials(request.user, cred_username)
    except ObjectDoesNotExist:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to delete " \
                    +f"credential {cred_username} as that user does not own that credential")
        messages.error(request, "no such username found for your user")
        return redirect("index")
    except MultipleObjectsReturned:
        logger.error(f"Multiple records exist for credential {cred_username} owned by {request.user.username} ({request.user.email})")
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
    logger.info(f"Sent data for credential {request.POST['username']} to user {request.user.username} ({request.user.email}) at "+request.META["REMOTE_ADDR"])
    return response


@login_required
def group_management(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested the group management page from "+request.META["REMOTE_ADDR"])
    
    # only staff can manage groups
    if not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"access the group management page, as that user is not a staff member")
        messages.error(request, "Not authorized to manage groups.")
        return redirect("index")
    return render(
        request, 'hopskotch_auth/group_management.html',
        dict(groups=Group.objects.all())
    )


@require_POST
@login_required
def create_group(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to create a group with name " \
                +request.POST.get("name","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    # only staff can create new groups
    if not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"create a group, as that user is not a staff member")
        messages.error(request, "Not authorized to create groups.")
        return redirect("index")
    
    if not "name" in request.POST or len(request.POST["name"])==0:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"create a group, as no valid group name was specified")
        messages.error(request, "Missing or invalid group name.")
        return redirect("create_group")
    
    group_name = request.POST["name"]
    # make sure that the group name is not already in use
    try:
        existing_group=Group.objects.get(name=group_name)
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"create a group named {group_name}, as that name is already in use")
        messages.error(request, "Group name already in use; please choose another.")
        return redirect("create_group")
    except ObjectDoesNotExist as dne:
        # this is good, the name is not in use and creation can proceed
        pass
    
    # no collision, so proceed with creating the group
    group = Group.objects.create(name=group_name)

    logger.info(f"Created group {group_name} with ID {group.id}")
    messages.info(request, "Created group \""+group_name+'"')
    base_edit_url = reverse("edit_group")
    return redirect(base_edit_url+"?group_id="+str(group.id))


@login_required
def edit_group(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to edit group ID " \
                +request.GET.get("group_id","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    if not "group_id" in request.GET or len(request.GET["group_id"])==0:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"edit a group, as no valid group ID was specified")
        messages.error(request, "Missing or invalid group ID.")
        return redirect("index")
    
    group_id = request.GET["group_id"]
    
    # only group owners and staff can edit groups
    if not is_group_owner(request.user,group_id) and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"edit the group with ID {group_id}, as that user is not a group owner or staff member")
        messages.error(request, "Not authorized to manage that group.")
        return redirect("index")

    try:
        group = Group.objects.get(id=group_id)
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"edit the group with ID {group_id}, as no such group exists")
        messages.error(request, "No such group.")
        return redirect("index")

    memberships = []
    for membership in GroupMembership.objects.filter(group_id=group_id):
        user = get_user_model().objects.get(id=membership.user_id)
        memberships.append({"user_id":user.id,"user_name":user.username,"user_email":user.email,"status":membership.status})
    
    all_users = get_user_model().objects.all().values("id","username","email")

    return render(
        request, "hopskotch_auth/edit_group.html",
        dict(group=group, memberships=memberships, all_users=all_users, 
             topics=KafkaTopic.objects.filter(owning_group=group_id))
    )


@require_POST
@login_required
def delete_group(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to delete group ID " \
                +request.POST.get("group_id","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    # only staff can delete groups
    if not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"delete the group with ID {group_id}, as that user is not a staff member")
        messages.error(request, "Not authorized to delete groups.")
        return redirect("index")
    
    if not "group_id" in request.POST or len(request.POST["group_id"])==0:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"delete a group, as no valid group ID was specified")
        messages.error(request, "Missing or invalid group ID.")
        return redirect("group_management")
    
    try:
        group = Group.objects.get(id=request.POST["group_id"])
        # clean up any permissions that users had by being in the group
        for membership in GroupMembership.objects.filter(group_id=group.id):
            removeUserGroupPermissions(membership.user, group.id)
        group_name = group.name
        group.delete()
        logger.info(f"Deleted group {group_name} with ID {group.id}")
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"delete the group with ID {group_id}, as no such group exists")
        messages.error(request, "No such group to delete.")
        return redirect("group_management")
    
    messages.info(request, "Group "+group_name+" deleted")
    return redirect("group_management")


@login_required
def credential_management(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested the global credential management page from "+request.META["REMOTE_ADDR"])
    
    # only staff can manage others' credentials
    if not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"access the credential management page, as that user is not a staff member")
        messages.error(request, "Not authorized to manage credentials.")
        return redirect("index")
    return render(
        request, 'hopskotch_auth/credential_management.html',
        dict(credentials=SCRAMCredentials.objects.all().select_related("owner"))
    )


# Also used to add group members
@require_POST
@login_required
def change_membership_status(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to change user ID " \
                +request.POST.get("user_id","<unset>")+"'s status in group ID " \
                +request.POST.get("group_id","<unset>")+" to "+request.POST.get("status","<unset>") \
                +" from "+request.META["REMOTE_ADDR"])
    
    print("change_membership_status")
    if not "group_id" in request.POST or len(request.POST["group_id"])==0:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"change a user's group membership status, as no valid group ID was specified")
        messages.error(request, "Missing or invalid group ID.")
        return redirect("index")
    if not "user_id" in request.POST or len(request.POST["user_id"])==0:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"change a user's group membership status, as no valid user ID was specified")
        messages.error(request, "Missing or invalid user ID.")
        return redirect("index")
    if not "status" in request.POST or len(request.POST["status"])==0 \
      or not request.POST["status"] in MembershipStatus.__members__:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"change a user's group membership status, as no valid membership status was specified")
        messages.error(request, "Missing or invalid membership status.")
        return redirect("index")
    
    group_id = request.POST["group_id"]
    user_id=request.POST["user_id"]
    status=request.POST["status"]
    
    # only group owners and staff can add users to groups/change membership status
    if not is_group_owner(request.user,group_id) and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"change a user's status in the group with ID {group_id}, as that user is not a group owner or staff member")
        messages.error(request, "Not authorized to manage that group.")
        return redirect("index")
    
    try:
        group = Group.objects.get(id=group_id)
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"change a user's status in the group with ID {group_id}, as no such group exists")
        messages.error(request, "No such group.")
        return redirect("index")

    try:
        target_user = get_user_model().objects.get(id=user_id)
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"change a user's status in the group with ID {group_id}, as the target user does not exist")
        messages.error(request, "No such user.")
        return redirect("index")

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
    logger.info(f"User {request.user.username} ({request.user.email}) requested to remove user ID " \
                +request.POST.get("user_id","<unset>")+" from group ID " \
                +request.POST.get("group_id","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    if not "group_id" in request.POST or len(request.POST["group_id"])==0:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"remove a user from a group, as no valid group ID was specified")
        messages.error(request, "Missing or invalid group ID.")
        return redirect("index")
    if not "user_id" in request.POST or len(request.POST["user_id"])==0:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"remove a user from a group, as no valid user ID was specified")
        messages.error(request, "Missing or invalid user ID.")
        return redirect("index")
    
    group_id = request.POST["group_id"]
    user_id=request.POST["user_id"]
    
    # only group owners and staff can remove users from groups
    if not is_group_owner(request.user,group_id) and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"remove a user from the group with ID {group_id}, as that user is not a group owner or staff member")
        messages.error(request, "Not authorized to manage that group.")
        return redirect("index")
    
    try:
        group = Group.objects.get(id=group_id)
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"remove a user from the group with ID {group_id}, as no such group exists")
        messages.error(request, "No such group.")
        return redirect("index")

    try:
        target_user = get_user_model().objects.get(id=user_id)
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"remove the user with ID {user_id} from the group with ID {group_id}, as no such user exists")
        messages.error(request, "No such user.")
        return redirect("index")

    try:
        membership = GroupMembership.objects.get(user_id=user_id, group_id=group_id)
        removeUserGroupPermissions(user_id, group_id)
        membership.delete()
    except ObjectDoesNotExist as dne:
        # apparently we need do nothing
        pass

    logger.info(f"Removed user {target_user.username} ({target_user.email}) from" \
                +f" group {group.name}")
    messages.info(request, "Removed user from group.")
    base_edit_url = reverse("edit_group")
    return redirect(base_edit_url+"?group_id="+group_id)


@require_POST
@login_required
def create_topic(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to create a topic with name " \
                +request.POST.get("topic_name","<unset>")+" owned by group ID " \
                +request.POST.get("group_id","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    if not "group_id" in request.POST or not validate_topic_name(request.POST["group_id"]):
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"create a topic, as no valid owning group ID was specified")
        messages.error(request, "Missing or invalid owning group ID.")
        return redirect("index")
    
    group_id = request.POST["group_id"]

    # make sure that the requestor has the authority to do this
    if not is_group_owner(request.user, group_id) and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"create a topic owned by the group with ID {group_id}, as that user is not a group owner or staff member")
        messages.error(request, "Not authorized to create topics owned by that group.")
        return redirect("index")
    # if the requesting user is a member of the proposed owning group it also proves that the 
    # group exists, so we don't need to check that separately

    if not "topic_name" in request.POST or not validate_topic_name(request.POST["topic_name"]):
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"create a topic, as no valid topic name was specified")
        messages.error(request, "Missing or invalid topic name.")
        base_edit_url = reverse("edit_group")
        return redirect(base_edit_url+"?group_id="+group_id)
    
    topic_name = request.POST["topic_name"]

    # make sure that the topic name is not already in use
    try:
        existing_topic = KafkaTopic.objects.get(name=topic_name)
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"create a topic, as the name was already in use")
        messages.error(request, "Topic name already in use; please choose another.")
        base_edit_url = reverse("edit_group")
        return redirect(base_edit_url+"?group_id="+group_id)
    except ObjectDoesNotExist as dne:
        # this is good, the name is not in use and creation can proceed
        pass

    group = Group.objects.get(id=group_id)
    
    topic = KafkaTopic.objects.create(name=topic_name, owning_group=group)
    # assign complete access to the owning group
    GroupKafkaPermission.objects.create(principal=group, topic=topic, operation=KafkaOperation.All)

    logger.info(f"Created topic {topic_name} owned by group {group.name}")
    messages.info(request, "Created topic \""+topic_name+'"')
    base_edit_url = reverse("edit_topic")
    return redirect(base_edit_url+"?topic_id="+str(topic.id))


@login_required
def edit_topic(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to edit topic ID " \
                +request.GET.get("topic_id","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    if not "topic_id" in request.GET:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"edit a topic, as no topic ID was specified")
        messages.error(request, "Missing topic ID.")
        return redirect("index")
    
    try:
        topic = KafkaTopic.objects.get(id=request.GET["topic_id"])
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"edit a topic, as no matching topic exists")
        messages.error(request, "No such topic.")
        return redirect("index")

    owning_group = topic.owning_group
    # only group owners and staff may use this page 
    if not is_group_owner(request.user, owning_group.id) and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"edit a topic owned by the group with ID {owning_group.id}, as that user is not a group owner or staff member")
        messages.error(request, "Not authorized to manage that topic.")
        return redirect("index")

    permissions = []
    for perm in topic.groupkafkapermission_set.all().select_related("principal"):
        permissions.append({"group_name":perm.principal.name, "group_id":perm.principal.id, 
                           "operation":perm.operation, "id":perm.id})

    all_groups = Group.objects.all()
    operations = KafkaOperation.__members__.keys()

    return render(
        request, "hopskotch_auth/edit_topic.html",
        dict(topic=topic, owning_group=owning_group, permissions=permissions, all_groups=all_groups, operations=operations)
        )


@require_POST
@login_required
def set_topic_public_read_access(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to set topic ID " \
                +request.POST.get("topic_id","<unset>")+" public read access to " \
                +request.POST.get("public","<unset>")+" from "+request.META["REMOTE_ADDR"])

    if not "topic_id" in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"set public access to a topic, as no topic ID was specified")
        messages.error(request, "Missing topic ID.")
        return redirect("index")
    if not "public" in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"set public access to a topic, as no public status was specified")
        messages.error(request, "Missing public status.")
        return redirect("index")

    try:
        topic = KafkaTopic.objects.get(id=request.POST["topic_id"])
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"set public access to a topic, as no matching topic exists")
        messages.error(request, "No such topic.")
        return redirect("index")

    owning_group = topic.owning_group
    # only group owners and staff make a topic (not) publicly readable 
    if not is_group_owner(request.user, owning_group.id) and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"edit a topic owned by the group with ID {owning_group.id}, as that user is not a group owner or staff member")
        messages.error(request, "Not authorized to manage that topic.")
        return redirect("index")
    
    topic.publicly_readable = bool(request.POST["public"])
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
    logger.info(f"User {request.user.username} ({request.user.email}) requested to delete topic ID " \
                +request.POST.get("topic_id","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    if not "topic_id" in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"delete a topic, as no topic ID was specified")
        messages.error(request, "Missing topic ID.")
        return redirect("index")
    
    try:
        topic = KafkaTopic.objects.get(id=request.POST["topic_id"])
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"delete a topic, as no matching topic exists")
        messages.error(request, "Invalid topic ID.")
        return redirect("index")
    
    # make sure that the requestor has the authority to do this
    if not is_group_owner(request.user, topic.owning_group) and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"delete a topic owned by the group {topic.owning_group}, as that user is not a group owner or staff member")
        messages.error(request, "Not authorized to delete that topic.")
        return redirect("index")
    
    topic_name = topic.name
    deleteTopicPermissions(topic.id)
    topic.delete()
    logger.info(f"Deleted topic {topic_name}")
    messages.info(request, "Deleted topic \""+topic_name+'"')
    return redirect("index")


@require_POST
@login_required
def add_group_permission(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to grant group ID " \
                +request.POST.get("group_id","<unset>")+" " \
                +request.POST.get("operation","<unset>")+" permission for topic ID " \
                +request.POST.get("topic_id","<unset>")+" from "+request.META["REMOTE_ADDR"])
                
    if not "topic_id" in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"grant a group permission to access a topic, as no topic ID was specified")
        messages.error(request, "Missing topic ID.")
        return redirect("index")
    if not "group_id" in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"grant a group permission to access a topic, as no group ID was specified")
        messages.error(request, "Missing group ID.")
        return redirect("index")
    if not "operation" in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"grant a group permission to access a topic, as no operation was specified")
        messages.error(request, "Missing operation.")
        return redirect("index")

    topic_id = request.POST["topic_id"]
    group_id = request.POST["group_id"]
    try:
        operation = KafkaOperation[request.POST["operation"]]
    except KeyError as ke:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"grant a group permission to access a topic, as the specified operation was not valid")
        messages.error(request, "Invalid operation.")
        return redirect("index")
    
    # make sure the target topic exists
    try:
        topic = KafkaTopic.objects.get(id=topic_id)
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"grant a group permission to access a topic, as no matching topic exists")
        messages.error(request, "Invalid topic ID.")
        return redirect("index")

    # make sure that the requestor has the authority to do this
    if not is_group_owner(request.user.id, topic.owning_group) and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"grant a group permission to access a topic owned by the group {topic.owning_group}, as that user is not a group owner or staff member")
        messages.error(request, "Not authorized to manage that topic.")
        return redirect("index")
    # if the requesting user is a member of the proposed owning group it also proves that the 
    # group exists, so we don't need to check that separately

    addKafkaPermissionForGroup(group_id, topic, operation)
    
    logger.info(f"Granted group ID {group_id} {operation.name} permission to topic {topic.name}")
    messages.info(request, "Granted "+operation.name+" permission to topic \""+topic.name+'"')
    base_edit_url = reverse("edit_topic")
    return redirect(base_edit_url+"?topic_id="+topic_id)


@require_POST
@login_required
def remove_group_permission(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to revoke group permission with ID " \
                +request.POST.get("perm_id","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    if not "perm_id" in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"revoke a group permission to access a topic, as no permission ID was specified")
        messages.error(request, "Missing permission ID.")
        return redirect("index")
    
    try:
        permission = GroupKafkaPermission.objects.get(id=request.POST["perm_id"])
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"revoke a group permission to access a topic, as no matching permission exists")
        messages.error(request, "Invalid permission ID.")
        return redirect("index")

    topic = permission.topic
    owning_group = topic.owning_group

    # make sure that the requestor has the authority to do this
    if not is_group_owner(request.user, owning_group) and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"revoke a group's permission to access a topic owned by the group {owning_group}, as that user is not a group owner or staff member")
        messages.error(request, "Not authorized to manage that topic.")
        return redirect("index")

    removeKafkaPermissionForGroup(permission, permission.principal)
    
    logger.info(f"Revoked group ID {group_id} {operation.name} permission to topic {topic.name}")
    messages.info(request, "Revoked "+permission.operation.name+" permission for topic \""+topic.name+'"')
    base_edit_url = reverse("edit_topic")
    return redirect(base_edit_url+"?topic_id="+str(topic.id))


@login_required
def edit_credential(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to edit permissions for credential " \
                +request.GET.get("cred_username","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    if not "cred_username" in request.GET:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"edit a credential, as no credential username was specified")
        messages.error(request, "Missing credential name.")
        return redirect("index")
    
    try:
        credential = SCRAMCredentials.objects.get(username=request.GET["cred_username"])
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"edit a credential, as no matching credential exists")
        messages.error(request, "No such credential.")
        return redirect("index")

    owner = credential.owner
    # only credential owners and staff may use this page 
    if request.user!=owner and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"edit a credential, as that user is not the credential owner or a staff member")
        messages.error(request, "Not authorized to manage that credential.")
        return redirect("index")

    permissions = []
    for perm in credential.credentialkafkapermission_set.all().select_related('topic'):
        permissions.append({"topic_name":perm.topic.name, "operation":perm.operation, "id":perm.id})

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
    logger.info(f"User {request.user.username} ({request.user.email}) requested to add a permission " \
                +request.POST.get("perm","<unset>")+" to credential " \
                +request.POST.get("cred_username","<unset>")+" from "+request.META["REMOTE_ADDR"])
    
    if not "cred_username" in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"add a permission to a credential, as no credential username was specified")
        messages.error(request, "Missing credential name.")
        return redirect("index")
    if "perm" not in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"add a permission to a credential, as no permission was specified")
        messages.error(request, "Missing permission description.")
        return redirect("index")
    
    try:
        credential = SCRAMCredentials.objects.get(username=request.POST["cred_username"])
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"add a permission to a credential, as no matching credential exists")
        messages.error(request, "No such credential.")
        return redirect("index")
    
    try:
        parent_id, _, operation = decode_cred_permission(request.POST["perm"])
    except ValueError as ve:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"add a permission to a credential, as the specified permission was malformed")
        messages.error(request, "Invalid permission data.")
        return redirect("index")

    # make sure the requesting user actually has the rights to add this permission to this credential

    # the user must be the credential owner or a staff member
    if request.user!=credential.owner and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"add a permission to a credential, as that user is not the credential owner or a staff member")
        messages.error(request, "Not authorized to manage that credential.")
        return redirect("index")

    # the referenced parent (group) permission must exist and 
    # the user must belong to the group with which it is associated
    try:
        parent_perm = GroupKafkaPermission.objects.get(id=parent_id)
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"add a permission to a credential, as the referenced parent permission does not exist")
        messages.error(request, "Invalid permission.")
        return redirect("index")
    if not is_group_member(credential.owner, parent_perm.principal):
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"add a permission to a credential, as credential owner does not have access to the specified parent permission")
        messages.error(request, "Invalid permission.")
        return redirect("index")

    # the referenced group permission must actually grant the permission being requested
    if parent_perm.operation!=operation and parent_perm.operation!=KafkaOperation.All:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"add a permission to a credential, as the referenced parent permission does not grant the specified operation")
        messages.error(request, "Invalid operation.")
        return redirect("index")

    try:
        # if the permission already exists, we should not add it
        # note that we don't care whether parent prmission is an exact match
        CredentialKafkaPermission.objects.get(principal=credential, topic=parent_perm.topic, operation=operation)
        messages.info(request, str(operation)+" permission for topic "+parent_perm.topic.name+" was already present")
    except ObjectDoesNotExist as dne:
        CredentialKafkaPermission.objects.create(principal=credential, parent=parent_perm, topic=parent_perm.topic, operation=operation)
        logger.info("Added "+str(operation)+" permission for topic "+parent_perm.topic.name+" to credential "+credential.username)
        messages.info(request, "Added "+str(operation)+" permission for topic "+parent_perm.topic.name)

    base_edit_url = reverse("edit_credential")
    return redirect(base_edit_url+"?cred_username="+credential.username)


@require_POST
@login_required
def remove_credential_permission(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to remove a permission ID " \
                +request.POST.get("perm_id","<unset>")+" from a credential from "+request.META["REMOTE_ADDR"])
    
    if "perm_id" not in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"remove a permission from a credential, as no permission ID was specified")
        messages.error(request, "Missing permission ID.")
        return redirect("index")
    
    try:
        perm = CredentialKafkaPermission.objects.get(id=request.POST["perm_id"])
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"remove a permission from a credential, as the specified permission does not exist")
        messages.error(request, "No such permission record.")
        return redirect("index")

    # the user must be the credential owner or a staff member
    if request.user!=perm.principal.owner and not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +f"remove a permission from a credential, as that user is not the credential owner or a staff member")
        messages.error(request, "Not authorized to manage that credential.")
        return redirect("index")
    
    perm.delete()

    logger.info(request, "Removed "+str(perm.operation)+" permission for topic "+perm.topic.name+" from credential "+perm.principal)
    messages.info(request, "Removed "+str(perm.operation)+" permission for topic "+perm.topic.name)
    base_edit_url = reverse("edit_credential")
    return redirect(base_edit_url+"?cred_username="+perm.principal.username)


@require_POST
@login_required
def suspend_credential(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to suspend the credential with ID " \
                +request.POST.get("cred_id","<unset>")+" from "+request.META["REMOTE_ADDR"])

    # only staff can suspend credentials
    if not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"suspend a credential, as that user is not a staff member")
        messages.error(request, "Not authorized to suspend credentials.")
        return redirect("index")

    if "cred_id" not in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"add a permission to a credential, as no credential ID was specified")
        messages.error(request, "Missing credential ID.")
        return redirect("index")

    try:
        cred = SCRAMCredentials.objects.get(id=request.POST["cred_id"])
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"suspend a credential, as no matching credential exists")
        messages.error(request, "No such credential.")
        return redirect("index")

    if not cred.suspended: 
        cred.suspended = True
        cred.save()
        logger.info("Suspended credential "+cred.username)
        messages.info(request, "Suspended credential "+cred.username)

    base_edit_url = reverse("edit_credential")
    return redirect(base_edit_url+"?cred_username="+cred.username)


@require_POST
@login_required
def unsuspend_credential(request):
    logger.info(f"User {request.user.username} ({request.user.email}) requested to un-suspend the credential with ID " \
                +request.POST.get("cred_id","<unset>")+" from "+request.META["REMOTE_ADDR"])

    # only staff can unsuspend credentials
    if not request.user.is_staff:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"un-suspend a credential, as that user is not a staff member")
        messages.error(request, "Not authorized to remove credential suspensions.")
        return redirect("index")

    if "cred_id" not in request.POST:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"un-suspend a credential, as no credential ID was specified")
        messages.error(request, "Missing credential ID.")
        return redirect("index")

    try:
        cred = SCRAMCredentials.objects.get(id=request.POST["cred_id"])
    except ObjectDoesNotExist as dne:
        logger.info(f"Ignored request by user {request.user.username} ({request.user.email}) to " \
                    +"un-suspend a credential, as no matching credential exists")
        messages.error(request, "No such credential.")
        return redirect("index")

    if cred.suspended:
        cred.suspended = False
        cred.save()
        logger.info("Un-suspended credential "+cred.username)
        messages.info(request, "Un-suspended credential "+cred.username)

    base_edit_url = reverse("edit_credential")
    return redirect(base_edit_url+"?cred_username="+cred.username)
