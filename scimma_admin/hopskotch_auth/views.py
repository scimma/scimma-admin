from typing import Any, Callable, Dict, TypeVar, cast

from tokenize import group
from urllib.request import HTTPRedirectHandler
from .apps import HopskotchAuthConfig
from django.shortcuts import render, redirect
from django.http import HttpRequest, HttpResponse, JsonResponse, HttpResponseRedirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist, MultipleObjectsReturned
from django.db import connection, transaction
from django.template import Library
from django.views.decorators.http import require_POST, require_GET
from django.urls import reverse
from wsgiref.util import FileWrapper
from io import StringIO
from django.views.decorators.csrf import csrf_exempt

from mozilla_django_oidc.auth import get_user_model

from .forms import *
from .directinterface import DirectInterface, Error
from .models import *

import logging

logger = logging.getLogger(__name__)

engine = DirectInterface()

MESSAGE_TAGS = {
        messages.DEBUG: 'alert-secondary',
        messages.INFO: 'alert-info',
        messages.SUCCESS: 'alert-success',
        messages.WARNING: 'alert-warning',
        messages.ERROR: 'alert-danger',
 }

class AuthenticatedHttpRequest(HttpRequest):
    user: User

WrappedFunc = TypeVar('WrappedFunc', bound=Callable[..., Any])

def admin_required(func: WrappedFunc) -> WrappedFunc:
    def admin_check(request: AuthenticatedHttpRequest, *args: Any, **kwargs: Dict[str,Any]) -> Any:
        is_admin = request.user.is_staff
        if is_admin:
            return func(request, *args, **kwargs)
        return render(request, 'hopskotch_auth/admin_required.html')
    return cast(WrappedFunc, admin_check)

def client_ip(request: HttpRequest) -> str:
    """Determine the original client IP address, taking into account headers set
    by the load balancer, if they exist.
    """
    if "X-Forwarded-For" in request.headers:
        header = request.headers["X-Forwarded-For"]
        if ',' in header:
            trusted_addr = header.split(',')[-1]
            return trusted_addr+f" (full X-Forwarded-For header: {header})"
        return header
    return request.META["REMOTE_ADDR"]

def download(request: AuthenticatedHttpRequest) -> HttpResponse:
    myfile = StringIO()
    myfile.write("username,password\n")
    myfile.write(f"{request.POST['username']},{request.POST['password']}")
    myfile.flush()
    myfile.seek(0) # move the pointer to the beginning of the buffer
    response = HttpResponse(FileWrapper(myfile), content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename=hop-credentials.csv'
    logger.info(f"Sent data for credential {request.POST['username']} to user "
                f"{request.user.username} ({request.user.email}) at {client_ip(request)}")
    return response

def log_request(request: AuthenticatedHttpRequest, description: str):
    logger.info(f"User {request.user.username} ({request.user.email}) requested "
                f"to {description} from {client_ip(request)}")

def redirect_with_error(request: AuthenticatedHttpRequest, operation: str, err: Error,
                        redirect_to: str, *redir_args, **redir_kwargs) -> HttpResponse:
    logger.info(f"Request by user {request.user.username} ({request.user.email} failed. "
                f"Operation={operation}, Reason={err.desc}")
    messages.error(request, err.desc)
    return redirect(redirect_to,  permanent=False, *redir_args, **redir_kwargs)

def json_with_error(request: AuthenticatedHttpRequest, operation: str, err: Error) -> JsonResponse:
    logger.info(f"Request by user {request.user.username} ({request.user.email} failed. "
                f"Operation={operation}, Reason={err.desc}")
    return JsonResponse(status=err.status, data={'error': err.desc})


@login_required
def index(request: AuthenticatedHttpRequest) -> HttpResponse:
    clean_credentials = []
    clean_memberships = []
    clean_topics = []

    creds_result = engine.get_user_credentials(request.user)
    if not creds_result:
        # we don't use redirect_with_error for these, because the place we would usually redirect would be
        # the index, and we don't want an infinite redirect loop if something goes wrong.
        messages.error(request, creds_result.err())
    else:
        for cred in creds_result.ok():
            clean_credentials.append({
                'username': cred.username,
                'created_at': cred.created_at.strftime("%Y/%m/%d %H:%M"),
                'description': cred.description
            })

    memberships_result = engine.get_user_group_memberships(request.user)
    if not memberships_result:
        messages.error(request, memberships_result.err().desc)
    else:
        for membership in memberships_result.ok():
            clean_memberships.append({
                'group_id': membership.group.id,
                'group_name': membership.group.name,
                'status': membership.status.name,
                'member_count': membership.group.members.count(),
            })

    topics_result = engine.get_user_accessible_topics(request.user)
    if not topics_result:
        messages.error(request, topics_result.err().desc)
    else:
        for topic, means in topics_result.ok():
            clean_topics.append({
                                'topic': topic.name,
                                'topic_description': topic.description,
                                'accessible_by': means
                                })

    return render(
        request, 'hopskotch_auth/index.html',
        {'credentials': clean_credentials, 'memberships': clean_memberships,
        'accessible_topics': clean_topics})


def login(request: AuthenticatedHttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    return render(request, 'hopskotch_auth/login.html',)


def logout(request: AuthenticatedHttpRequest) -> HttpResponse:
    return HttpResponse("you're logged out!")


def login_failure(request: AuthenticatedHttpRequest) -> HttpResponse:
    return render(request, 'hopskotch_auth/login_failure.html')

@login_required
def create_credential(request: AuthenticatedHttpRequest) -> HttpResponse:
    if request.method == 'POST':
        log_request(request, "create a new credential")
        form = CreateCredentialForm(request.POST)
        description = request.POST['desc_field']
        cred_result = engine.new_credential(request.user, description)
        if not cred_result:
            return redirect_with_error(request, "create_credential", cred_result.err(), 'index')

        username = cred_result.ok()['username']
        password = cred_result.ok()['password']
        messages.warning(request, 'PLEASE READ. This information will only be displayed once. '
                         'Please copy this information down and/or download it as a CSV file via the button below')
        return render(request, 'hopskotch_auth/finished_credential.html',
                    {
                        'cred_username': username,
                        'cred_password': password,
                        'cred_description': description,
                    })
    return render(request, 'hopskotch_auth/create_credential.html')

@login_required
def suspend_credential(request: AuthenticatedHttpRequest, credname: str='', redirect_to: str='index') -> HttpResponse:
    log_request(request, f"suspend credential {credname}")
    cred_result = engine.get_credential(request.user, credname)
    if not cred_result:
        messages.error(request, cred_result.err().desc)
    else:
        cred = cred_result.ok()
        if cred.suspended:
            result = engine.unsuspend_credential(request.user, cred)
        else:
            result = engine.suspend_credential(request.user, cred)
        if not result:
            messages.error(request, result.err().desc)
    if redirect_to == 'index':
        return redirect('index')
    elif redirect_to == 'admin':
        return redirect('admin_credential')
    return redirect('index')

@login_required
def manage_credential(request: AuthenticatedHttpRequest, credname: str) -> HttpResponse:
    if request.method == 'POST':
        log_request(request, f"update credential {credname} description")
        # TODO: data pulled from request.POST must be sanitized
        result = engine.update_credential(request.user, credname, request.POST['desc_field'])
        if not result:
            return redirect_with_error(request, "manage_credential", result.err(), 'index')
        return HttpResponseRedirect(request.path_info)

    log_request(request, f"manage credential {credname}")
    cred_result = engine.get_credential(request.user, credname)
    if not cred_result:
        return redirect_with_error(request, "manage_credential", cred_result.err(), 'index')
    cred = cred_result.ok()

    # Get all currently added permissions
    perms_result = engine.get_credential_permissions(request.user, cred.username)
    if not perms_result:
        return redirect_with_error(request, "manage_credential", perms_result.err(), 'index')
    # TODO: this code makes no sense; a credential has permissions to topics, and may have several for a
    # given topic, it does not have topics themselves
    added_topics = []
    easy_lookup = []
    for perm in perms_result.ok():
        if perm.topic.name not in easy_lookup:
            easy_lookup.append(perm.topic.name)
            added_topics.append({
                'topic': perm.topic.name,
                'description': perm.topic.description,
                'access_via': perm.parent.principal.name,
            })
    avail_perms = engine.get_available_credential_permissions(request.user)
    if not avail_perms:
        return redirect_with_error(request, "manage_credential", avail_perms.err(), 'index')
    avail_topics = [{"topic": x[0].topic.name,
                     "topic_description": x[0].topic.description,
                     "accessible_by": x[0].principal.name
                    } for x in avail_perms.ok() if x[0].topic.name not in easy_lookup]

    return render(request,
        'hopskotch_auth/manage_credential.html',
        {
            'accessible_topics': avail_topics,
            'added_topics': added_topics,
            'cur_username': cred.username,
            'cur_desc': cred.description})

@login_required
def create_group(request: AuthenticatedHttpRequest) -> HttpResponse:
    if request.method == 'POST':
        log_request(request, f"create a group with name {request.POST.get('name_field','<unset>')}")
        groupname = request.POST['name_field']
        descfield = request.POST['desc_field']
        create_result = engine.create_group(request.user, groupname, descfield)
        if not create_result:
            return redirect_with_error(request, "create_group", create_result.err(), 'index')
        return redirect('manage_group_members', groupname)
    users_result = engine.get_all_users()
    if not users_result:
        return redirect_with_error(request, "create_group", users_result.err(), 'index')
    form = CreateGroupForm()
    return render(request, 'hopskotch_auth/create_group.html', {'form': form, 'accessible_members': users_result.ok()})

# TODO: does this serve any purpose?
@login_required
def finished_group(request: AuthenticatedHttpRequest) -> HttpResponse:
    # Capture all objects in post, then submit to database
    return render(request, 'hopskotch_auth/index.html')

@login_required
def create_topic(request: AuthenticatedHttpRequest) -> HttpResponse:
    groups_result = engine.get_user_group_memberships(request.user)
    if not groups_result:
        redirect_with_error(request, "create_topic", groups_result.err(), 'index')
    all_groups = groups_result.ok()
    owned_groups = []
    available_groups = []
    for membership in all_groups:
        if membership == MembershipStatus.Owner:
            owned_groups.append(membership.group)
        available_groups.append(membership.group)
    if request.method == 'POST':
        if request.POST['submit'].lower() == 'select':
            owner = request.POST['submit_owner']
            form = CreateTopicForm(owning_group=owner)
            # TODO: Why is this a list since it appears it should contain only a single group?
            available_groups = [group for group in available_groups if group['group_name'] != owner]
            return render(request, 'hopskotch_auth/create_topic.html',
                          {'form': form, 'all_groups': available_groups, 'owning_group': owner})
        elif request.POST['submit'].lower() == 'create':
            log_request(request, f"create a topic with name {request.POST.get('name_field','<unset>')}"
                        f" owned by group {request.POST.get('owning_group_field','<unset>')}")
            owning_group_name = request.POST['owning_group_field']
            topic_name = request.POST['name_field']
            create_result = engine.create_topic(
                request.user,
                owning_group_name,
                topic_name,
                request.POST['desc_field'],
                True if 'visibility_field' in request.POST else False
            )
            if not create_result:
                redirect_with_error(request, "create_topic", Error('Topic creation failed, please try again. '
                                    'Reason: '+groups_result.err().desc, 400), 'index')
            topic_name = owning_group_name+'.'+topic_name
            for x in request.POST:
                # TODO: among other issues, this encoding does not cover the full range of possible permissions
                if x.startswith('group_name['):
                    idx = x[len('group_name['):-1]
                    group_name = request.POST[f'group_name[{idx}]']
                    read_perm = True if f'read_[{idx}]' in request.POST else False
                    write_perm = True if f'write_[{idx}]' in request.POST else False
                    if read_perm:
                        perm_result = engine.add_group_topic_permission(request.user, group_name,
                                                                        topic_name, KafkaOperation.Read)
                        if not perm_result:
                            messages.error(request=request, message=f'Failed to add read permission to {group_name}')
                    if write_perm:
                        perm_result = engine.add_group_topic_permission(request.user, group_name,
                                                                        topic_name, KafkaOperation.Write)
                        if not perm_result:
                            messages.error(request=request, message=f'Failed to add write permission to {group_name}')
            messages.success(request=request, message='Topic created successfully')
            return redirect('index') # TODO: should redirect to the management page for the topic
        else:
            messages.warning(request=request, message='Something went wrong')
            return redirect('index')
    form = CreateTopicForm()
    owner_form = SelectOwnerForm()
    return render(request, 'hopskotch_auth/create_topic.html', {'owner_form': owner_form, 'form': form, 'owned_groups': owned_groups, 'all_groups': available_groups})


@login_required
def manage_topic(request, topicname) -> HttpResponse:
    if request.method == 'POST':
        log_request(request, "modify the topic with name "
                    f"{request.POST.get('owning_group_field','<unset>')}."
                    f"{request.POST.get('name_field','<unset>')}")
        # TODO: splitting the topic name up and putting it back together like this is not necessary and will probably confuse users
        full_topic_name = '{}.{}'.format(
                request.POST['owning_group_field'],
                request.POST['name_field']
            )
        topic_result = engine.get_topic(full_topic_name)
        if not topic_result:
            redirect_with_error(request, "manage_topic", topic_result.err(), 'index')
        topic = topic_result.ok()
        # TODO: multiplexing different types of requests through the same function makes precise logging of requests difficult; this needs to be cleaned up
        if 'desc_field' in request.POST:
            update_result = engine.update_topic_description(request.user, topic, request.POST['desc_field'])
            if not update_result:
                redirect_with_error(request, "manage_topic", update_result.err(), request.path_info)
        if 'visibility_field' in request.POST:
            update_result = engine.update_topic_visibility(request.user, topic, request.POST['visibility_field'])
            if not update_result:
                redirect_with_error(request, "manage_topic", update_result.err(), request.path_info)
        return HttpResponseRedirect(request.path_info)
    topic_result = engine.get_topic(topicname)
    if not topic_result:
        redirect_with_error(request, "manage_topic", topic_result.err(), 'index')
    topic = topic_result.ok()

    access_result = engine.get_groups_with_access_to_topic(topic)
    if not access_result:
        redirect_with_error(request, "manage_topic", access_result.err(), 'index')
    groups_added = access_result.ok()

    groups_result = engine.get_all_groups()
    if not groups_result:
        redirect_with_error(request, "manage_topic", groups_result.err(), 'index')
    groups_available = groups_result.ok()

    cleaned_added = []
    cleaned_available = []
    for group in groups_available:
        is_added = False
        for added in groups_added:
            if group == added.principal:
                is_added = True
                break
        if is_added:
            cleaned_added.append(group.name)
        else:
            cleaned_available.append(group.name)
    return render(request,
            'hopskotch_auth/manage_topic.html',
            {'topic_owner': topic.owning_group.name,
            'topic_name': topic.name.split('.')[1],
            'topic_desc': topic.description,
            'is_visible': topic.publicly_readable,
            'all_groups': cleaned_available,
            'group_list': cleaned_added}
        )

@login_required
def manage_group_members(request, groupname) -> HttpResponse:
    if request.method == 'POST':
        log_request(request, f"modify the description of the group with name {groupname}")
        description = request.POST['desc_field']
        modify_result = engine.modify_group_description(groupname, description)
        if not modify_result:
            redirect_with_error(request, "modify_group_description", modify_result.err(),
                                'manage_group_members', groupname=groupname)
        else:
            messages.success(request, 'Successfully modified description')
        return redirect('manage_group_members', groupname=groupname)
    users_result = engine.get_all_users()
    if not users_result:
        redirect_with_error(request, "modify_group_description", users_result.err(), 'index')
    users = users_result.ok()
    group_result = engine.get_group(groupname)
    if not group_result:
        redirect_with_error(request, "modify_group_description", group_result.err(), 'index')
    group = group_result.ok()
    members_result = engine.get_group_members(group)
    if not members_result:
        redirect_with_error(request, "modify_group_description", members_result.err(), 'index')
    members = members_result.ok()
    # TODO: Quadratic-ish complexity needs fixing
    cleaned_users = []
    for user in users:
        is_member = False
        for membership in members:
            if user == membership.user:
                is_member = True
                break
        if not is_member:
            cleaned_users.append(user)
    clean_members = [m.user for m in members]

    form = ManageGroupMemberForm(group.name, group.description)
    return render(request, 'hopskotch_auth/manage_group_members.html',
                  {'form': form, 'members': clean_members, 'accessible_members': cleaned_users,
                  'groupname': groupname, 'cur_name': group.name, 'cur_description': group.description})

@login_required
def manage_group_topics(request, groupname) -> HttpResponse:
    if request.method == 'POST':
        log_request(request, f"modify the description of the group with name {groupname}")
        description = request.POST['desc_field']
        modify_result = engine.modify_group_description(groupname, description)
        if not modify_result:
            redirect_with_error(request, "manage_group_topics", modify_result.err(),
                                'manage_group_topics', groupname=groupname)
        else:
            messages.success(request, 'Successfully modified description')
        return redirect('manage_group_topics', groupname=groupname)
    group_result = engine.get_group(groupname)
    if not group_result:
        redirect_with_error(request, "manage_group_topics", group_result.err(), 'index')
    group = group_result.ok()
    topics_result = engine.get_group_topics(groupname)
    if not topics_result:
        redirect_with_error(request, "manage_group_topics", topics_result.err(), 'index')
    topics = topics_result.ok()
    # TODO: Is this supposed to be the topics the group owns (from get_group_topics) or the topics
    # to which the group has some access (from get_group_accessible_topics)
    clean_topics_added = {}
    for topic in topics:
        if topic.name not in clean_topics_added:
            clean_topics_added[topic.name] = {
                'topicname': topic.name,
                'description': topic.description,
                #'accessible_by': topic['accessible_by'], # not valid for a group
            }
    return render(request, 'hopskotch_auth/manage_group_topics.html',
                  {'topics': clean_topics_added.values(), 'groupname': group.name,
                  'cur_name': group.name, 'cur_description': group.description })

@admin_required
@login_required
def admin_credential(request: AuthenticatedHttpRequest) -> HttpResponse:
    log_request(request, "manage all credentials")
    creds_result = engine.get_all_credentials()
    if not creds_result:
        redirect_with_error(request, "admin_credential", creds_result.err(), 'index')
    clean_creds = [{
        'username': credential.owner.username,
        'credname': credential.username,
        'created_at': credential.created_at,
        'suspended': credential.suspended,
        'description': credential.description,
    } for credential in creds_result.ok()]
    return render(request, 'hopskotch_auth/admin_credential.html', {'all_credentials': clean_creds})

@admin_required
@login_required
def admin_topic(request: AuthenticatedHttpRequest) -> HttpResponse:
    log_request(request, "manage all topics")
    topics_result = engine.get_all_topics()
    if not topics_result:
        redirect_with_error(request, "admin_topic", topics_result.err(), 'index')
    clean_topics = [{
        'owning_group': topic.owning_group.name,
        'name': topic.name,
        'description': topic.description,
        'publicly_readable': topic.publicly_readable,
    } for topic in topics_result.ok()]
    return render(request, 'hopskotch_auth/admin_topic.html', {'all_topics': clean_topics})

@admin_required
@login_required
def admin_group(request: AuthenticatedHttpRequest) -> HttpResponse:
    log_request(request, "manage all groups")
    groups_result = engine.get_all_groups()
    if not groups_result:
        redirect_with_error(request, "admin_group", groups_result.err(), 'index')
    clean_groups = [{
        'name': group.name,
        'description': group.description,
        'members': [member.user.username
                    for member in engine.get_group_members(group).ok()]
    } for group in groups_result.ok()]
    for group in clean_groups:
        group['mem_count'] = len(group['members'])
    return render(request, 'hopskotch_auth/admin_group.html', {'all_groups': clean_groups})

def add_credential_permission(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"add a/an {request.POST.get('perm_perm','<unset>')} permission "
                f"for topic {request.POST.get('perm_name','<unset>')} to credential "
                f"{request.POST.get('credname','<unset>')}")
    if request.method != 'POST' or \
        'credname' not in request.POST or \
        'perm_name' not in request.POST or \
        'perm_perm' not in request.POST:
        return JsonResponse(status=400, data={
            'error': 'Bad request'
        })
    credname = request.POST['credname']
    topic_name = request.POST['perm_name']
    perm_perm = request.POST['perm_perm']
    operation = KafkaOperation[perm_perm]
    add_result = engine.add_credential_permission(request.user, credname, topic_name, operation)
    if not add_result:
        return json_with_error(request, "add_credential_permission", add_result.err())
    return JsonResponse(data={}, status=200)

def remove_credential_permission(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"remove a/an {request.POST.get('perm_perm','<unset>')} permission "
                f"for topic {request.POST.get('perm_name','<unset>')} to credential "
                f"{request.POST.get('credname','<unset>')}")
    if request.method != 'POST' or \
        'credname' not in request.POST or \
        'perm_name' not in request.POST or \
        'perm_perm' not in request.POST:
        return json_with_error(request, "remove_credential_permission", Error("Invalid request", 400))
    credname = request.POST['credname']
    topic_name = request.POST['perm_name']
    perm_perm = request.POST['perm_perm']
    operation = KafkaOperation[perm_perm]
    remove_result = engine.remove_credential_permission(request.user, credname, topic_name, operation)
    if not remove_result:
        return json_with_error(request, "remove_credential_permission", remove_result.err())
    return JsonResponse(data={}, status=200)

# TODO: Purpose of these functions completely impossible to determine from names.
# They appear to never be used?
'''
def add_topic_group(request: AuthenticatedHttpRequest) -> HttpResponse:
    topic_name = request.POST['topic_name']
    owning_group = request.POST['owning_group']
    new_group = request.POST['group_name']
    operation = request.POST['group_perm']
    full_topic_name = f'{owning_group}.{topic_name}'
    status_code, _ = engine.add_group_to_topic(full_topic_name, new_group, operation)
    if status_code is not None:
        messages.error(request, status_code)
    return redirect('manage_topic', full_topic_name)

def remove_topic_group(request: AuthenticatedHttpRequest) -> HttpResponse:
    topic_name = request.POST['topic_name']
    owning_group = request.POST['owning_group']
    new_group = request.POST['group_name']
    operation = request.POST['group_perm']
    full_topic_name = f'{owning_group}.{topic_name}'
    status_code, _ = engine.remove_group_from_topic(full_topic_name, new_group, operation)
    if status_code is not None:
        messages.error(request, status_code)
    return redirect('manage_topic', full_topic_name)

@login_required
def add_group_topic(request: AuthenticatedHttpRequest) -> HttpResponse:
    print(request.POST)
    topicname = request.POST['topicname']
    groupname = topicname.split('.')[0]
    permission = request.POST['op_perm']
    status_code, _ = engine.add_topic_to_group(groupname, topicname, permission)
    if status_code is not None:
        messages.error(request, status_code)
        return redirect('index')
    return redirect('manage_group_topic', groupname)

@login_required
def remove_group_topic(request: AuthenticatedHttpRequest) -> HttpResponse:
    topicname = request.POST['topicname']
    perm = request.POST['topic_pub']
    groupname = request.POST['groupname']
    status_code, _ = engine.remove_topic_from_group(groupname, topicname, perm)
    if status_code is not None:
        messages.error(request, status_code)
        return redirect('index')
    return redirect('manage_group_topics', groupname)
'''

@login_required
def group_add_member(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"add a user ({request.POST.get('username','<unset>')})"
                f" to group {request.POST.get('groupname','<unset>')}")
    groupname = request.POST['groupname']
    username = request.POST['username']
    add_result = engine.add_member_to_group(groupname, username, MembershipStatus.Member)
    if not add_result:
        return json_with_error(request, "group_add_member", add_result.err())
    return JsonResponse(data={}, status=200)

@login_required
def group_remove_member(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"remove a user {request.POST.get('username','<unset>')}"
                f" from group {request.POST.get('groupname','<unset>')}")
    groupname = request.POST['groupname']
    username = request.POST['username']
    remove_result = engine.remove_member_from_group(groupname, username)
    if not remove_result:
        return json_with_error(request, "group_remove_member", remove_result.err())
    return JsonResponse(data={}, status=200)

@login_required
def user_change_status(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"change the status of user {request.POST.get('username','<unset>')}"
                f" in group {request.POST.get('groupname','<unset>')} to "
                f"{request.POST.get('status','<unset>')}")
    groupname = request.POST['groupname']
    username = request.POST['username']
    membership = request.POST['status'].lower()
    member_status = MembershipStatus[membership]
    status_result = engine.change_user_group_status(username, groupname, member_status)
    if not status_result:
        return json_with_error(request, "user_change_status", status_result.err())
    return JsonResponse(data={}, status=200)

@login_required
def get_topic_permissions(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"fetch group {request.POST.get('groupname','<unset>')}'s"
                f" permissions for topic {request.POST.get('topicname','<unset>')}")
    groupname = request.POST['groupname']
    topicname = request.POST['topicname']
    perms_result = engine.get_group_permissions_for_topic(groupname, topicname)
    if not perms_result:
        return json_with_error(request, "get_topic_permissions", perms_result.err())
    data = [str(p.operation) for p in perms_result.ok()]
    return JsonResponse(data={'data': data}, status=200)

# TODO: Why is this called '_in_group'?
@login_required
def create_topic_in_group(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"create a topic named {request.POST.get('topicname','<unset>')},"
                f" owned by group {request.POST.get('groupname','<unset>')}")
    groupname = request.POST['groupname']
    topicname = request.POST['topicname']

    create_result = engine.create_topic(request.user, groupname, topicname, '', False)
    if not create_result:
        return json_with_error(request, "create_topic", create_result.err())
    full_topic_name = '{}.{}'.format(groupname, topicname)
    editpath = reverse('manage_topic', args=(full_topic_name,))
    return JsonResponse(data={'editpath': editpath}, status=200)

# TODO: Function name makes no sense; unclear what this should do. Appears to be unused?
'''
@login_required
def add_topic_to_group(request: AuthenticatedHttpRequest) -> JsonResponse:
    topicname = request.POST['topicname']
    groupname = request.POST['groupname']

    status_code, _ = engine.add_topic_to_group(groupname, topicname)
    if status_code is not None:
        return JsonResponse(data={'error': status_code}, status=404)
    return JsonResponse(data={}, status=200)
'''

# TODO: Function name makes no sense; unclear what this should do. Appears to be unused?
'''
@login_required
def remove_topic_from_group(request: AuthenticatedHttpRequest) -> JsonResponse:
    topicname = request.POST['topicname']
    groupname = request.POST['groupname']
    status_code, _ = engine.delete_topic(request.user.username, groupname, topicname)
    if status_code is not None:
        return JsonResponse(data={'error': status_code}, status=404)
    return JsonResponse(data={}, status=200)
'''

# TODO: Appears to be unused
'''
@login_required
def get_available_credential_topics(request: AuthenticatedHttpRequest) -> JsonResponse:
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    perms_result = engine.get_available_credential_permissions(request.user.username)
    if not perms_result:
        return json_with_error(request, "get_available_credential_topics", perms_result.err(), 400)
    # TODO: Why is this filtering by tpic name?
    # Computing all possible permissions is fairly expensive, we should do it as few times as possible,
    # not repeat for each topic. If the UI wants to display split by topic it should do that itself.
    possible_perms = []
    for perm in avail_perms:
        if perm['topic'] == topicname:
            possible_perms.append(perm)
    existing_result = engine.get_credential_permissions_for_topic(credname, topicname)
    if not existing_result:
        return json_with_error(request, "get_available_credential_topics", existing_result.err(), 400)
    cred_perms = [str(p.operation) for p in existing_result.ok()]
    return JsonResponse(data={'data': possible_perms, 'cred_data': cred_perms}, status=200)
'''

# TODO: When is this operation useful?
@login_required
def add_all_credential_permission(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"add all permission to topic {request.POST.get('topicname','<unset>')}"
                f" to credential {request.POST.get('credname','<unset>')}")
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    existing_result = engine.get_credential_permissions_for_topic(credname, topicname)
    if not existing_result:
        return json_with_error(request, "add_all_credential_permission", existing_result.err())
    existing = existing_result.ok()
    if any(p.operation == KafkaOperation.All for p in existing):
        # Nothing to do
        return JsonResponse(data={}, status=200)
    # Remove all individual permissions
    for existing_perm in existing:
        remove_result = engine.remove_credential_permission(request.user, credname, topicname, existing_perm.operation)
        if not remove_result:
            return json_with_error(request, "add_all_credential_permission", remove_result.err())
    # add the All permission
    add_result = engine.add_credential_permission(request.user, credname, topicname, KafkaOperation.All)
    if not add_result:
        return json_with_error(request, "add_all_credential_permission", add_result.err())
    return JsonResponse(data={}, status=200)

'''
def get_user_available_permissions(user):
    possible_permissions = {}
    for membership in user.groupmembership_set.all():
        group = membership.group
        group_permissions = GroupKafkaPermission.objects.filter(principal=group).select_related('topic')
        for permission in group_permissions:
            if permission.topic.name not in possible_permissions:
                possible_permissions[permission.topic.name] = {
                    'topic': permission.topic.name,
                    'description': permission.topic.description,
                    'access_via': permission.principal.name,
                    'operation': permission.operation.name
                }
    possible_permissions = list(possible_permissions.values())
    # sort and eliminate duplicates
    # sort on operation
    #possible_permissions.sort(key=lambda p: p[1])
    possible_permissions.sort(key=lambda p: p['operation'])
    # sort on topic names, because that looks nice for users, but since there is a bijection
    # between topic names and IDs this will place all matching topic IDs together in blocks
    # in some order
    #possible_permissions.sort(key=lambda p: p[0])
    possible_permissions.sort(key=lambda p: p['topic'])

    def equivalent(p1, p2):
        return p1['topic'] == p2['topic']
        #return p1['topic_id'] == p2['topic_id'] and p1['operation'] == p2['operation']
        #return p1[0] == p2[0] and p1[-1] == p2[-1]

    # remove adjacent (practical) duplicates which have different permission IDs
    dedup = []
    last = None
    for p in possible_permissions:
        if last is None or not equivalent(last,p):
            dedup.append(p)
            last=p

    return dedup
'''
