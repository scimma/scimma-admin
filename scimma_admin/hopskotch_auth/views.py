from tokenize import group
from urllib.request import HTTPRedirectHandler
from .apps import HopskotchAuthConfig
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
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
from .directinterface import DirectInterface
from .apiinterface import ApiInterface
from .models import *

import logging

logger = logging.getLogger(__name__)

if HopskotchAuthConfig.connection == 'direct':
    engine = DirectInterface()
elif HopskotchAuthConfig.connection == 'api':
    engine = ApiInterface()

MESSAGE_TAGS = {
        messages.DEBUG: 'alert-secondary',
        messages.INFO: 'alert-info',
        messages.SUCCESS: 'alert-success',
        messages.WARNING: 'alert-warning',
        messages.ERROR: 'alert-danger',
 }

def admin_required(func):
    def admin_check(*args, **kwargs):
        print('***********************************')
        request = args[0]
        status_code, is_admin = engine.is_user_admin(request.user.username)
        print(args)
        print(request)
        print(status_code)
        print(is_admin)
        print('***********************************')
        if status_code is not None:
            messages.error(request, 'Something went wrong with checking for admin status')
            return redirect('index')
        is_admin = is_admin['is_admin']
        if is_admin:
            return func(*args, **kwargs)
        return render(request, 'hopskotch_auth/admin_required.html')
    return admin_check

def client_ip(request):
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

def download(request):
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

def redirect_with_error(request, operation, reason, redirect_to):
    logger.info(f"Ignored request by user {request.user.username} ({request.user.email}. "
                f"Operation={operation}, Reason={reason}")
    messages.error(request, reason)
    return redirect(redirect_to)


@login_required
def index(request):
    _, credentials = engine.get_user_credentials(request.user.username)
    _, memberships = engine.get_user_groups(request.user.username)
    _, accessible_topics = engine.get_user_topics(request.user.username)
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


def login_failure(request):
    return render(request, 'hopskotch_auth/login_failure.html')

@login_required
def create_credential(request):
    if request.method == 'POST':
        form = CreateCredentialForm(request.POST)
        description = request.POST['desc_field']
        status_code, return_dict = engine.new_credential(request.user.username, description)

        if status_code is not None:
            messages.warning(request, 'Credential not successfully made')
            return redirect('index')
        
        username, password = return_dict['username'], return_dict['password']
        perms = []
        for x in request.POST:
            #if x.startswith('group_name'):
            # Collect indexed group_name, desc_field and read/write
            if 'group_name' in x:
                end_idx = x.find(']')
                start_idx = len('group_name[')
                idx = int(x[start_idx:end_idx])
                group_name = request.POST['group_name[{}]'.format(idx)]
                desc_field = request.POST['desc_field[{}]'.format(idx)]
                perms = {'read': False, 'write': False}
                if 'read_[{}]'.format(idx) in request.POST:
                    engine.add_permission(request.user.username, username, *(group_name.split('.')), 'read')
                if 'write_[{}]'.format(idx) in request.POST:
                    engine.add_permission(request.user.username, username, *(group_name.split('.')), 'write')
        messages.warning(request, 'PLEASE READ. This information will only be displayed once. Please copy this information down and/or download it as a CSV via the button below')
        return render(request, 'hopskotch_auth/finished_credential.html',
                    {
                        'cred_username': username,
                        'cred_password': password,
                        'cred_description': description,
                    })
    status_code, accessible_topics = engine.user_accessible_topics(request.user.username)
    accessible_topics.sort(key=lambda t: t['topic'])
    if status_code is not None:
        messages.error(request, 'Bad HTTP request for getting user topics, redirected to main page')
        return redirect('index')
    form = CreateCredentialForm()
    return render(request, 'hopskotch_auth/create_credential.html',
        dict(accessible_topics=accessible_topics, form=form)
    )

@login_required
def delete_credential(request, credname, redirect_to='index'):
    status_code, return_dict = engine.delete_credential(request.user.username, credname)
    if status_code is not None:
        messages.error(request, 'Something went wrong. Credential not deleted')
    if redirect_to == 'index':
        return redirect('index')
    elif redirect_to == 'admin':
        return redirect('admin_credential')
    return redirect('index')

@login_required
def suspend_credential(request, credname='', redirect_to='index'):
    status_code, cred = engine.get_credential_info(request.user.username, credname)
    if cred['suspended']:
        status_code, return_dict = engine.unsuspend_credential(request.user, credname)
    else:
        status_code, return_dict = engine.suspend_credential(request.user, credname)
    if redirect_to == 'index':
        return redirect('index')
    elif redirect_to == 'admin':
        return redirect('admin_credential')
    return redirect('index')

@login_required
def manage_credential(request, username):
    if request.method == 'POST':
        try:
            cred = SCRAMCredentials.objects.get(username=request.POST['name_field'])
        except ObjectDoesNotExist as dne:
            messages.error(request, f'Could not find credential with name {username}')
            return redirect('index')
        cred.description = request.POST['desc_field']
        cred.save()
        return HttpResponseRedirect(request.path_info)

    try:
        cred = SCRAMCredentials.objects.get(username=username)
    except ObjectDoesNotExist as dne:
        messages.error(request, f'Credential with name "{username}" could not be found')
        return redirect('index')
    
    # Get all currently added credentials
    cred_permissions = CredentialKafkaPermission.objects.filter(principal=cred)
    added_topics = []
    easy_lookup = []
    for cred_added in cred_permissions:
        if cred_added.topic.name not in easy_lookup:
            easy_lookup.append(cred_added.topic.name)
            added_topics.append({
                'topic': cred_added.topic.name,
                'description': cred_added.topic.description,
                'access_via': cred_added.parent.principal.name,
            })

    avail_topics = get_user_available_permissions(request.user)
    avail_topics = [x for x in avail_topics if x['topic'] not in easy_lookup]
    
    return render(request, 
        'hopskotch_auth/manage_credential.html', 
        {
            'accessible_topics': avail_topics, 
            'added_topics': added_topics, 
            'cur_username': cred.username, 
            'cur_desc': cred.description})

@login_required
def create_group(request):
    if request.method == 'POST':
        # Step 1: Remove all users
        # Step 2: Get all users added from request into list with {name: perm} pairings
        # Step 3: Use engine to add users back
        groupname = request.POST['name_field']
        descfield = request.POST['desc_field']
        status, _ = engine.create_group(request.user.username, groupname, descfield)
        if status is not None:
            messages.error(request, status)
            return redirect('index')
        status, _ = engine.add_member_to_group(groupname, request.user.username, 'owner')
        if status is not None:
            messages.error(request, status)
            return redirect('index')
        return redirect('manage_group_members', groupname)
    status_code, accessible_members = engine.get_all_users()
    form = CreateGroupForm()
    return render(request, 'hopskotch_auth/create_group.html', {'form': form, 'accessible_members': accessible_members})

@login_required
def finished_group(request):
    # Capture all objects in post, then submit to databnase
    return render(request, 'hopskotch_auth/index.html')

@login_required
def create_topic(request):
    status_code, all_groups = engine.get_user_groups(request.user.username)
    owned_groups = []
    available_groups = []
    for group in all_groups:
        if group['status'].lower() == 'owner':
            owned_groups.append(group)
        available_groups.append(group)
    if request.method == 'POST':
        if request.POST['submit'].lower() == 'select':
            owner = request.POST['submit_owner']
            form = CreateTopicForm(owning_group=owner)
            available_groups = [group for group in available_groups if group['group_name'] != owner]
            return render(request, 'hopskotch_auth/create_topic.html', {'form': form, 'all_groups': available_groups, 'owning_group': owner})
        elif request.POST['submit'].lower() == 'create':
            status_code, _ = engine.create_topic(
                request.user.username,
                request.POST['owning_group_field'],
                request.POST['name_field'],
                request.POST['desc_field'],
                True if 'visibility_field' in request.POST else False
            )
            if status_code is not None:
                messages.error(request=request, message='Topic creation failed, please try again')
                return redirect('index')
            for x in request.POST:
                if x.startswith('group_name['):
                    idx = x[len('group_name['):-1]
                    group_name = request.POST[f'group_name[{idx}]']
                    read_perm = True if f'read_[{idx}]' in request.POST else False
                    write_perm = True if f'write_[{idx}]' in request.POST else False
                    if read_perm:
                        status_code, _ = engine.add_group_to_topic(
                            request.POST['name_field'],
                            request.POST['owning_group_field'],
                            'read'
                        )
                        if status_code is not None:
                            messages.error(request=request, message=f'Failed to add read permission to {group_name}')
                            return redirect('index')
                    if write_perm:
                        status_code, _ = engine.add_group_to_topic(
                            request.POST['name_field'],
                            request.POST['owning_group_field'],
                            'write'
                        )
                        if status_code is not None:
                            messages.error(request=request, message=f'Failed to add read permission to {group_name}')
                            return redirect('index')
            messages.success(request=request, message='Topic created successfully')
            return redirect('index')
        else:
            messages.warning(request=request, message='Something went wrong')
            return redirect('index')
    form = CreateTopicForm()
    owner_form = SelectOwnerForm()
    return render(request, 'hopskotch_auth/create_topic.html', {'owner_form': owner_form, 'form': form, 'owned_groups': owned_groups, 'all_groups': available_groups})




@login_required
def manage_topic(request, topicname):
    if request.method == 'POST':
        full_topic_name = '{}.{}'.format(
                request.POST['owning_group_field'],
                request.POST['name_field']
            )
        try:
            topic = KafkaTopic.objects.get(name=full_topic_name)
        except ObjectDoesNotExist as dne:
            messages.error(request, f'Could not update "{full_topic_name}" as it was not found')
            return redirect('index')
        topic.description = request.POST['desc_field']
        if 'visibility_field' in request.POST:
            topic.publicly_readable = True
        else:
            topic.publicly_readable = False
        topic.save()
        return HttpResponseRedirect(request.path_info)
    group, topic = topicname.split('.')
    try:
        topic = KafkaTopic.objects.get(name=topicname)
    except ObjectDoesNotExist as dne:
        messages.error(request, f'Topic "{topicname}" cannot be found')
        return redirect('index')
    groups_added = GroupKafkaPermission.objects.filter(topic=topic)
    if request.user.is_staff:
        groups_available = GroupMembership.objects.filter(user=request.user)
    else:
        groups_available = GroupMembership.objects.filter(user=request.user, status=MembershipStatus.Owner)
    
    cleaned_added = []
    cleaned_available = []
    for group in groups_available:
        is_added = False
        for added in groups_added:
            if group.group == added.principal:
                is_added = True
                break
        if is_added:
            cleaned_added.append(group.group.name)
        else:
            cleaned_available.append(group.group.name)
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
def manage_group_members(request, groupname):
    if request.method == 'POST':
        description = request.POST['desc_field']
        status_code, _ = engine.modify_group_description(groupname, description)
        if status_code is not None:
            messages.error(request, status_code)
        else:
            messages.success(request, 'Successfully modified description')
        return redirect('manage_group_members', groupname=groupname)
    status_code, users = engine.get_all_users()
    status_code, group_obj = engine.get_group_info(groupname)
    status_code, clean_members = engine.get_group_members(groupname)
    cleaned_users = []
    for user in users:
        is_member = False
        for member in clean_members:
            if user['username'] == member['username']:
                is_member = True
                break
        if not is_member:
            cleaned_users.append(user)

    form = ManageGroupMemberForm(group_obj['name'], group_obj['description'])
    return render(request, 'hopskotch_auth/manage_group_members.html', {'form': form, 'members': clean_members, 'accessible_members': cleaned_users, 'groupname': groupname, 'cur_name': group_obj['name'], 'cur_description': group_obj['description']})

@login_required
def manage_group_topics(request, groupname):
    if request.method == 'POST':
        description = request.POST['desc_field']
        status_code, _ = engine.modify_group_description(groupname, description)
        if status_code is not None:
            messages.error(request, status_code)
        else:
            messages.success(request, 'Successfully modified description')
        return redirect('manage_group_members', groupname=groupname)
    status_code, group_obj = engine.get_group_info(groupname)
    if status_code is not None:
        print(status_code)
    status_code, topics_added = engine.get_group_topics(groupname)
    if status_code is not None:
        print(status_code)
        messages.error(request, status_code)
    status_code, user_topics = engine.get_user_topics(request.user.username)
    if status_code is not None:
        print(status_code)
        messages.error(request, status_code)
    clean_topics_addible = []
    clean_topics_added = {}
    print('------------------------------------------------------------------------------------')
    print(groupname)
    print(group_obj)
    print(topics_added)
    print(user_topics)
    print('------------------------------------------------------------------------------------')
    for topic in topics_added:
        if topic['topicname'] not in clean_topics_added:
            clean_topics_added[topic['topicname']] = {
                'topicname': topic['topicname'],
                'description': topic['description'],
                'accessible_by': topic['accessible_by'],
            }
    return render(request, 'hopskotch_auth/manage_group_topics.html', {'topics': clean_topics_added.values(), 'groupname': groupname, 'cur_name': group_obj['name'], 'cur_description': group_obj['description'] })

@admin_required
@login_required
def admin_credential(request):
    status_code, clean_creds = engine.get_all_credentials()
    return render(request, 'hopskotch_auth/admin_credential.html', {'all_credentials': clean_creds})

@admin_required
@login_required
def admin_topic(request):
    status_code, clean_topics = engine.get_all_topics()
    return render(request, 'hopskotch_auth/admin_topic.html', {'all_topics': clean_topics})

@admin_required
@login_required
def admin_group(request):
    status_code, clean_groups = engine.get_all_groups()
    for group in clean_groups:
        group['mem_count'] = len(group['members'])
    return render(request, 'hopskotch_auth/admin_group.html', {'all_groups': clean_groups})

def add_credential_permission(request):
    if request.method != 'POST' or \
        'credname' not in request.POST or \
        'perm_name' not in request.POST or \
        'perm_perm' not in request.POST:
        return JsonResponse(status=400, data={
            'error': 'Bad request'
        })
    credname = request.POST['credname']
    perm_name = request.POST['perm_name']
    perm_perm = request.POST['perm_perm']
    group, topic = perm_name.split('.')
    status_code, _ = engine.add_permission(request.user.username, credname, group, topic, perm_perm.lower())
    if status_code is not None:
        return JsonResponse(status=404, data={'error': status_code})
    return JsonResponse(data={}, status=200)

def remove_credential_permission(request):
    if request.method != 'POST' or \
        'credname' not in request.POST or \
        'perm_name' not in request.POST or \
        'perm_perm' not in request.POST:
        messages.error(request, 'Error in removing credential permission')
        return redirect('index')
    credname = request.POST['credname']
    perm_name = request.POST['perm_name']
    perm_perm = request.POST['perm_perm']
    group, topic = perm_name.split('.')
    status_code, _ = engine.remove_permission(request.user.username, credname, group, topic, perm_perm.lower())
    if status_code is not None:
        messages.error(request, status_code)
    return JsonResponse(data={}, status=200)

def add_topic_group(request):
    topic_name = request.POST['topic_name']
    owning_group = request.POST['owning_group']
    new_group = request.POST['group_name']
    operation = request.POST['group_perm']
    full_topic_name = f'{owning_group}.{topic_name}'
    status_code, _ = engine.add_group_to_topic(full_topic_name, new_group, operation)
    if status_code is not None:
        messages.error(request, status_code)
    return redirect('manage_topic', full_topic_name)

def remove_topic_group(request):
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
def add_group_topic(request):
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
def remove_group_topic(request):
    topicname = request.POST['topicname']
    perm = request.POST['topic_pub']
    groupname = request.POST['groupname']
    status_code, _ = engine.remove_topic_from_group(groupname, topicname, perm)
    if status_code is not None:
        messages.error(request, status_code)
        return redirect('index')
    return redirect('manage_group_topics', groupname)

@login_required
def group_add_member(request):
    groupname = request.POST['groupname']
    username = request.POST['username']
    status_code, _ = engine.add_member_to_group(groupname, username, 'member')
    if status_code is not None:
        return JsonResponse(data={}, status=404)
    return JsonResponse(data={}, status=200)

@login_required
def group_remove_member(request):
    groupname = request.POST['groupname']
    username = request.POST['username']
    status_code, _ = engine.remove_member_from_group(groupname, username)
    if status_code is not None:
        return JsonResponse(data={}, status=404)
    return JsonResponse(data={}, status=200)

@login_required
def user_change_status(request):
    groupname = request.POST['groupname']
    username = request.POST['username']
    membership = request.POST['status'].lower()
    status_code, _ = engine.change_user_group_status(username, groupname, membership)
    if status_code is not None:
        return JsonResponse(data={}, status=404)
    return JsonResponse(data={}, status=200)

@login_required
def get_topic_permissions(request):
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
    groupname = request.POST['groupname']
    topicname = request.POST['topicname']
    status_code, data = engine.get_topic_permissions(groupname, topicname)
    if len(data) > 0 and data == ['All']:
        data = all_perms
    if status_code is not None:
        return JsonResponse(data={}, status=404)
    return JsonResponse(data={'data': data}, status=200)

@login_required
def bulk_set_topic_permissions(request):
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']

    groupname = request.POST['groupname']
    topicname = request.POST['topicname']
    permissions = request.POST.getlist('permissions')

    status_code, data = engine.get_topic_permissions(groupname, topicname)

    # These are used for debugging purposes, you don't NEED these but if you need to make sure it is working properly printing them is helpful
    to_remove = []
    to_add = []

    # This scheme does not use the 'All' permission, all legacy ones using 'All' will be accepted but subsequently converted away on first edit
    if data == ['All']:
        if permissions == all_perms:
            print('All is already set')
            return JsonResponse(data={}, status=200)
        else:
            data = []
            status_code, _ = engine.remove_topic_permission(request.user.username, groupname, topicname, 'All')
            if status_code is not None:
                return JsonResponse(data={}, status=404)

    for perm in permissions:
        if perm not in data:
            to_add.append(perm)
            status_code, _ = engine.add_topic_permission(request.user.username, groupname, topicname, perm)
            if status_code is not None:
                print('Error adding ' + perm)
                return JsonResponse(data={'error': 'Error adding ' + perm}, status=404)
    
    for perm in data:
        if perm not in permissions:
            to_remove.append(perm)
            status_code, _ = engine.remove_topic_permission(request.user.username, groupname, topicname, perm)
            if status_code is not None:
                print('Error removing ' + perm)
                return JsonResponse(data={'error': 'Error removing ' + perm}, status=404)
    
    return JsonResponse(data={}, status=200)

@login_required
def create_topic_in_group(request):
    groupname = request.POST['groupname']
    topicname = request.POST['topicname']

    status_code, _ = engine.create_topic(request.user.username, groupname, topicname, '', False)
    if status_code is not None:
        print(status_code)
        print('From create topic')
        return JsonResponse(data={'error': status_code}, status=404)
    topicname = '{}.{}'.format(groupname, topicname)
    editpath = reverse('manage_topic', args=(topicname,))
    return JsonResponse(data={'editpath': editpath}, status=200)

@login_required
def add_topic_to_group(request):
    topicname = request.POST['topicname']
    groupname = request.POST['groupname']

    status_code, _ = engine.add_topic_to_group(groupname, topicname)
    if status_code is not None:
        return JsonResponse(data={'error': status_code}, status=404)
    return JsonResponse(data={}, status=200)

@login_required
def remove_topic_from_group(request):
    topicname = request.POST['topicname']
    groupname = request.POST['groupname']
    status_code, _ = engine.delete_topic(request.user.username, groupname, topicname)
    if status_code is not None:
        return JsonResponse(data={'error': status_code}, status=404)
    return JsonResponse(data={}, status=200)

@login_required
def get_available_credential_topics(request):
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    status_code, avail_perms = engine.get_available_credential_permissions(request.user.username)
    if status_code is not None:
        return JsonResponse(data={}, status_code=404)
    possible_perms = []
    for perm in avail_perms:
        if perm['topic'] == topicname:
            possible_perms.append(perm)
    status_code, cred_perms = engine.get_permissions_on_credential(credname, topicname)
    if 'All' in cred_perms:
        cred_perms = all_perms
    print('------------------------------------------------------------------------------------')
    print(credname)
    print(topicname)
    print([x['operation'] for x in possible_perms])
    print(cred_perms)
    print('------------------------------------------------------------------------------------')
    return JsonResponse(data={'data': possible_perms, 'cred_data': cred_perms}, status=200)

@login_required
def bulk_set_credential_permissions(request):
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    groupname = topicname.split('.')[0]
    permissions = request.POST.getlist('permissions')
    status_code, cred_perms = engine.get_permissions_on_credential(credname, topicname)
    print('------------------------------------------------------------------------------------')
    print(credname)
    print(topicname)
    print(groupname)
    print(permissions)
    print(cred_perms)
    print('------------------------------------------------------------------------------------')
    if 'All' in cred_perms:
        if permissions == all_perms:
            return JsonResponse(data={}, status=200)
        cred_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
        status_code, _ = engine.remove_permission(request.user.username, credname, groupname, topicname, 'All')
        if status_code is not None:
            return JsonResponse(data={'error': status_code}, status=404)
        for perm in cred_perms:
            status_code, _ = engine.add_permission(request.user.username, credname, groupname, topicname, perm)
    for perm in cred_perms:
        if perm not in permissions:
            status_code, _ = engine.remove_permission(request.user.username, credname, groupname, topicname, perm)
            if status_code is not None:
                print(status_code)
                print('Removing {} not found'.format(perm))
                return JsonResponse(data={'error': status_code}, status=404)
    for perm in permissions:
        if perm not in cred_perms:
            status_code, _ = engine.add_permission(request.user.username, credname, groupname, topicname, perm)
            if status_code is not None:
                print(status_code)
                print('Adding {} not found'.format(perm))
                return JsonResponse(data={'error': status_code}, status=404)
    return JsonResponse(data={}, status=200)

@login_required
def delete_all_credential_permissions(request):
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    groupname = topicname.split('.')[0]
    print('----------------------------------------------------------------------')
    print(credname)
    print(topicname)
    print(groupname)
    print('----------------------------------------------------------------------')
    status_code, cred_perms = engine.get_permissions_on_credential(credname, topicname)
    if status_code is not None:
        return JsonResponse(data={'error': status_code}, status=404)
    for perm in cred_perms:
        status_code, _ = engine.remove_permission(request.user.username, credname, groupname, topicname, perm)
        if status_code is not None:
            print('Error removing permission {}'.format(perm))
            return JsonResponse(data={'error': status_code}, status=404)
    return JsonResponse(data={}, status=200)

@login_required
def add_all_credential_permission(request):
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    groupname = topicname.split('.')[0]
    print('----------------------------------------------------------------------')
    print(credname)
    print(topicname)
    print(groupname)
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
    status_code, cred_perms = engine.get_permissions_on_credential(credname, topicname)
    if status_code is not None:
        print('Issues with getting permissions')
        return JsonResponse(data={'error': status_code}, status=404)
    print(cred_perms)
    if 'All' in cred_perms:
        status_code, _ = engine.remove_permission(request.user.username, credname, groupname, topicname, 'All')
        if status_code is not None:
            print('Found "All" but could not remove it')
            return JsonResponse(data={'error': status_code}, status=404)
    print('----------------------------------------------------------------------')

    #status_code, _ = engine.add_permission(request.user.username, credname, groupname, topicname, 'All')
    for perm in all_perms:
        status_code, _ = engine.add_permission(request.user.username, credname, groupname, topicname, perm)
        if status_code is not None:
            print('Could not add {} permission'.format(perm))
            return JsonResponse(data={'error': status_code}, status=404)
    return JsonResponse(data={}, status=200)

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