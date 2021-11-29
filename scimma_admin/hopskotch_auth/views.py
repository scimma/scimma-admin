from .apps import HopskotchAuthConfig
from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
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



from mozilla_django_oidc.auth import get_user_model

from .forms import *

from .directinterface import DirectInterface
from .apiinterface import ApiInterface

import logging

logger = logging.getLogger(__name__)

if HopskotchAuthConfig.connection == 'direct':
    engine = DirectInterface()
elif HopskotchAuthConfig.connection == 'api':
    engine = ApiInterface()

def admin_required(func):
    def admin_check(*args, **kwargs):
        request = args[0]
        status_code, is_admin = engine.is_user_admin(request.user.username)
        if status_code is not None:
            messages.error(request, 'Something went wrong with checking for admin status')
            return redirect('index')
        is_admin = is_admin['is_admin']
        if is_admin:
            return func(*args, **kwargs)
        return render(request, 'hopskotch_auth/admin_required.html')
    return admin_check

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
            messages.warning(request, status_code)
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
        messages.error(request, status_code)
    if redirect_to == 'index':
        return redirect('index')
    elif redirect_to == 'admin':
        return redirect('admin_credential')
    return redirect('index')

@login_required
def suspend_credential(request, credname='', redirect_to='index'):
    status_code, cred = engine.get_credential_info(request.user.username, credname)
    if status_code is not None:
        messages.error(request, status_code)
        return redirect('index')
    if cred['suspended']:
        status_code, return_dict = engine.unsuspend_credential(request.user, credname)
        if status_code is not None:
            messages.error(request, status_code)
    else:
        status_code, return_dict = engine.suspend_credential(request.user, credname)
        if status_code is not None:
            messages.error(request, status_code)
    if redirect_to == 'index':
        return redirect('index')
    elif redirect_to == 'admin':
        return redirect('admin_credential')
    return redirect('index')

@login_required
def manage_credential(request, username):
    if request.method == 'POST':
        status_code, _ = engine.update_credential(request.user.username, username, request.POST['desc_field'])
        if status_code is not None:
            messages.error(request, status_code)
        return redirect('index')
    status_code, cred_info = engine.get_credential_info(request.user.username, username)
    if status_code is not None:
        messages.error(request, status_code)
    #status_code, accessible_topics = engine.get_credential_topic_info(request.user.username, username)
    status_code, added_permissions = engine.get_credential_permissions(request.user.username, username)
    if status_code is not None:
        messages.error(request, status_code)
    status_code, topics_to_return = engine.get_user_topics(request.user.username)
    if status_code is not None:
        messages.error(request, status_code)
    form = ManageCredentialForm(cur_username=username, cur_desc=cred_info['description'])
    return render(request, 'hopskotch_auth/manage_credential.html', {'credname': username, 'accessible_topics': topics_to_return, 'added_topics': added_permissions, 'form': form})

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
        return redirect('manage_group_members', groupname)
    status_code, accessible_members = engine.get_all_users()
    form = CreateGroupForm()
    return render(request, 'hopskotch_auth/create_group.html', {'form': form, 'accessible_members': accessible_members})
    '''
    if request.method == 'POST':
        group_name = request.POST['name_field']
        desc_field = request.POST['desc_field']
        status, _ = engine.create_group(request.user.username, group_name, desc_field)
        if status != None:
            messages.error(request, status)
            return redirect('index')
        print(request.POST)
        for x in request.POST:
            if x.startswith('mem_id'):
                idx = x[7:-1]
                username = request.POST[f'mem_id[{idx}]']
                statusname = request.POST[f'member_radio[{idx}]']
                status, _ = engine.add_member_to_group(group_name, username, statusname)
        messages.success(request, 'Group created successfully')
        return redirect('index')
    form = CreateGroupForm(request.POST)
    members = engine.get_all_users()
    return render(request, 'hopskotch_auth/create_group.html', { 'form': form, 'accessible_member': members })
    '''

@login_required
def finished_group(request):
    # Capture all objects in post, then submit to databnase
    return render(request, 'hopskotch_auth/index.html')

def delete_group(request, groupname):
    status_code, _ = engine.delete_group(request.user.username, groupname)
    if status_code is not None:
        messages.error(request, status_code)
    if 'redirect_to' in request.POST and request.POST['redirect_to'] == 'admin':
        return redirect('admin_group')
    else:
        return redirect('index')

@login_required
def create_topic(request):
    status_code, all_groups = engine.get_user_groups(request.user.username)
    if status_code is not None:
        messages.error(request, status_code)
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
                messages.error(request, status_code)
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
        # Step 0: Get group + topic from topicname
        # Step 1: Clear all permissions (except owning group) from topic
        # Step 2: Coalesse group+topic+permissions from POST
        # Step 3: Add them all back as the user added
        return redirect('index')
    group, topic = topicname.split('.')
    status_code, topic_obj = engine.get_topic_info(group, topic)
    if status_code is not None:
        messages.error(request, 'Error in managing topic, returning to main page')
        return redirect('index')
    
    form = ManageTopicForm(group, topic, topic_obj['description'], topic_obj['publicly_readable'])
    status_code, group_list = engine.get_groups_by_topic(topicname)
    if status_code is not None:
        messages.error(request, status_code)
        return redirect('index')
    status_code, all_groups = engine.get_user_memberships(request.user.username)
    if status_code is not None:
        messages.error(request, status_code)
        return redirect('index')
    return render(request, 'hopskotch_auth/manage_topic.html', {'form': form, 'group_list': group_list, 'all_groups': all_groups, 'topic_name': topic, 'owning_group': group})

def delete_topic(request, topicname):
    group, topic = topicname.split('.')
    status_code, _ = engine.delete_topic(request.user.username, group, topicname)
    if status_code is not None:
        messages.error(request, status_code)
    return redirect('index')

@login_required
def manage_group_members(request, groupname):
    if request.method == 'POST':
        # Step 1: Remove all users
        # Step 2: Get all users added from request into list with {name: perm} pairings
        # Step 3: Use engine to add users back
        return redirect('index')
    status_code, group_obj = engine.get_group_info(groupname)
    if status_code is not None:
        messages.error(request, status_code)
    status_code, clean_members = engine.get_group_members(groupname)
    if status_code is not None:
        messages.error(request, status_code)
    status_code, accessible_members = engine.get_all_users()
    cleaned_users = []
    for member in accessible_members:
        exists = False
        for clean_mem in clean_members:
            if clean_mem['username'] == member['username']:
                exists = True
        if not exists:
            cleaned_users.append(member)
    form = ManageGroupMemberForm(group_obj['name'], group_obj['description'])
    return render(request, 'hopskotch_auth/manage_group_members.html', {'form': form, 'members': clean_members, 'accessible_members': cleaned_users, 'groupname': groupname})

@login_required
def manage_group_topics(request, groupname):
    if request.method == 'POST':
        # Step 1: Clear all topics
        # Step 2: Coalless all topics currently added
        # Step 3: Iterate over added topics and call engine
        return redirect('index')
    status_code, group_obj = engine.get_group_info(groupname)
    if status_code is not None:
        messages.error(request, status_code)
    form = ManageGroupTopicForm(group_obj['name'], group_obj['description'])
    status_code, clean_topics = engine.get_group_topics(groupname)
    if status_code is not None:
        messages.error(request, status_code)
    status_code, topics_to_return = engine.get_user_topics(request.user.username)
    if status_code is not None:
        messages.error(request, status_code)
    return render(request, 'hopskotch_auth/manage_group_topics.html', {'form': form, 'topics': clean_topics, 'groupname': groupname, 'accessible_topics': topics_to_return })

@admin_required
@login_required
def admin_credential(request):
    status_code, clean_creds = engine.get_all_credentials()
    if status_code is not None:
        messages.error(request, status_code)
    return render(request, 'hopskotch_auth/admin_credential.html', {'all_credentials': clean_creds})

@admin_required
@login_required
def admin_topic(request):
    status_code, clean_topics = engine.get_all_topics()
    if status_code is not None:
        messages.error(request, status_code)
    return render(request, 'hopskotch_auth/admin_topic.html', {'all_topics': clean_topics})

@admin_required
@login_required
def admin_group(request):
    status_code, clean_groups = engine.get_all_groups()
    if status_code is not None:
        messages.error(request, status_code)
    for group in clean_groups:
        group['mem_count'] = len(group['members'])
    return render(request, 'hopskotch_auth/admin_group.html', {'all_groups': clean_groups})

def add_credential_permission(request):
    if request.method != 'POST' or \
        'credname' not in request.POST or \
        'perm_name' not in request.POST or \
        'perm_perm' not in request.POST:
        messages.error(request, 'Error in adding credential permission')
        return redirect('index')
    credname = request.POST['credname']
    perm_name = request.POST['perm_name']
    perm_perm = request.POST['perm_perm']
    group, topic = perm_name.split('.')
    status_code, _ = engine.add_permission(request.user.username, credname, group, topic, perm_perm.lower())
    if status_code is not None:
        messages.error(request, status_code)
    return redirect('manage_credential', credname)

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
    return redirect('manage_credential', credname)

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

def remove_group_topic(request):
    topic_name = request.POST['topic_name']
    topic_desc = request.POST['topic_desc']
    topic_pub = request.POST['topic_pub']
    group_name = request.POST['group_name']
    return redirect('manage_group_topics', group_name)

def group_add_member(request):
    groupname = request.POST['groupname']
    username = request.POST['username']
    referer = request.POST['referer']
    status_code, _ = engine.add_member_to_group(groupname, username, 'member')
    return redirect(referer, groupname)

def group_remove_member(request):
    groupname = request.POST['groupname']
    username = request.POST['username']
    status_code, _ = engine.remov
    return redirect('manage_group_members', groupname)

def user_change_status(request):
    groupname = request.POST['groupname']
    username = request.POST['username']
    if request.POST['membership'].lower() == 'member':
        membership = 'owner'
    else:
        membership = 'member'
    status_code, _ = engine.change_user_group_status(username, groupname, membership)
    if status_code is not None:
        messages.error(request, status_code)
    return redirect('manage_group_members', groupname)