from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction

from .models import *

@login_required
def add_all_credential_permission(request):
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    groupname = topicname.split('.')[0]

    try:
        topic = KafkaTopic.objects.get(name=topicname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Cannot find topic "{topicname}"'})
    memberships = GroupMembership.objects.filter(user=request.user)
    possible_permissions = []
    for membership in memberships:
        perms = GroupKafkaPermission.objects.filter(principal=membership.group, topic=topic, operation=KafkaOperation.All)
        if perms.exists():
            possible_permissions = [p.value for _, p in KafkaOperation.__members__.items()]
            break
        perms = GroupKafkaPermission.objects.filter(principal=membership.group, topic=topic)
        for perm in perms:
            if perm.operation not in possible_permissions:
                possible_permissions.append(perm.operation)
    return JsonResponse(data={}, status=200)

@login_required
def get_available_credential_topics(request):
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    possible_perms = []
    cred_perms = []
    for membership in GroupMembership.objects.filter(user=request.user):
        group = membership.group
        group_permission = GroupKafkaPermission.objects.filter(principal=group).select_related('topic')
        for permission in group_permission:
            if permission.operation == KafkaOperation.All:
                for subpermissions in KafkaOperation.__members__.items():
                    possible_perms.append({
                        'topic_id': permission.topic.id,
                        'topic': permission.topic.name,
                        'description': permission.topic.description,
                        'access_via': permission.principal.name,
                        'operation': subpermissions[1].name,
                    })
            else:
                possible_perms.append({
                    'topic_id': permission.topic.id,
                    'topic': permission.topic.name,
                    'description': permission.topic.description,
                    'access_via': permission.principal.name,
                    'operation': permission.operation.name,
                })
    
    possible_perms.sort(key=lambda p: p['operation'])
    possible_perms.sort(key=lambda p: p['topic'])
    def equivalent(p1, p2):
        return p1['topic_id'] == p2['topic_id'] and p1['operation'] == p2['operation']
    
    cleaned_perms = []
    last = None
    for p in possible_perms:
        if last is None or not equivalent(last, p):
            cleaned_perms.append(p)
            last = p
    
    try:
        cred = SCRAMCredentials.objects.get(username=credname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Credential "{credname}" does not exist'}, status=404)
    try:
        topic = KafkaTopic.objects.get(name=topicname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Topic "{topicname}" does not exist'}, status=404)
    added_perms = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic)
    cred_perms = []
    if added_perms.exists():
        cred_perms = [x.operation.name for x in added_perms]

    return JsonResponse(data={'data': cleaned_perms, 'cred_data': cred_perms}, status=200)

@login_required
def get_group_permissions(request):
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
    topicname = request.POST['topicname']
    groupname = request.POST['groupname']
    try:
        group = Group.objects.get(name=groupname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Group "{groupname}" does not exist'}, status=404)
    try:
        topic = KafkaTopic.objects.get(name=topicname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Topic "{topicname}" does not exist'}, status=404)
    group_perms = GroupKafkaPermission.objects.filter(principal=group, topic=topic)
    perms = []
    if group_perms.exists():
        perms = [x.operation.name for x in group_perms]
    return JsonResponse(data={'permissions': perms}, status=200)

@login_required
def bulk_set_group_permissions(request):
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
    topicname = request.POST['topicname']
    groupname = request.POST['groupname']
    new_perms = request.POST.getlist('permissions')
    if new_perms == ['All']:
        new_perms = all_perms
    try:
        group = Group.objects.get(name=groupname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Group "{groupname}" does not exist'}, status=404)
    try:
        topic = KafkaTopic.objects.get(name=topicname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Topic "{topicname}" does not exist'}, status=404)
    group_perms = GroupKafkaPermission.objects.filter(principal=group, topic=topic)
    to_add = []
    to_remove = []
    if group_perms.exists():
        old_perms = [x.operation.name for x in group_perms]
        if 'All' in old_perms:
            print('All detected. Removing all and setting up for new perms')
            with transaction.atomic():
                group_perms.delete()
            to_add = [KafkaOperation[x] for x in new_perms]
        else:
            print('All not detected, making diff arrays')
            for perm in old_perms:
                if perm not in new_perms:
                    to_remove.append(KafkaOperation[perm])
            for perm in new_perms:
                if perm not in old_perms:
                    to_add.append(KafkaOperation[perm])
    else:
        to_add = [KafkaOperation[x] for x in new_perms]
    for perm in to_remove:
        GroupKafkaPermission.objects.get(principal=group, topic=topic, operation=perm).delete()
    for perm in to_add:
        new_obj = GroupKafkaPermission.objects.create(principal=group, topic=topic, operation=perm)
        new_obj.save()
    return JsonResponse(data={}, status=200)

def toggle_suspend_credential(request):
    credname = request.POST['credname']
    try:
        cred = SCRAMCredentials.objects.get(username=credname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Credential "{credname}" does not exist'}, status=404)
    if request.user == cred.owner or request.user.is_staff:
        is_suspended = not cred.suspended
        cred.suspended = not cred.suspended
        cred.save()
        return JsonResponse(data={'suspended': is_suspended}, status=200)
    return JsonResponse(data={'error': 'You must either be the owner or a staff member'}, status=403)

def delete_credential(request):
    credname = request.POST['credname']
    try:
        cred = SCRAMCredentials.objects.get(username=credname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Credential "{credname}" does not exist'}, status=404)
    if request.user == cred.owner or request.user.is_staff:
        cred.delete()
        return JsonResponse(data={}, status=200)
    else:
        return JsonResponse(data={'error': 'You must either be the owner or a staff member'}, status=403)

def delete_topic(request):
    topicname = request.POST['topicname']
    try:
        topic = KafkaTopic.objects.get(name=topicname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Topic "{topicname}" does not exist'}, status=404)
    owning_group = topic.owning_group
    user_membership = GroupMembership.objects.filter(user=request.user, group=owning_group, status=MembershipStatus.Owner)
    if user_membership.exists() or request.user.is_staff:
        topic.delete()
        with transaction.atomic():
            topic.delete()
        return JsonResponse(data={}, status=200)
    else:
        return JsonResponse(data={'error': f'You must either be an owner of the group "{topicname}" is a part of or be staff to delete this topic'}, status=403)

def delete_group(request):
    groupname = request.POST['groupname']
    try:
        group = Group.objects.get(name=groupname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Group "{groupname}" does not exist'}, status=404)
    if not request.user.is_staff:
        return JsonResponse(data={'error': f'You cannot delete "{groupname}" unless you are staff'}, status=403)
    group.delete()
    return JsonResponse(data={}, status=200)

def bulk_set_credential_permissions(request):
    all_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    groupname = topicname.split('.')[0]
    permissions = request.POST.getlist('permissions')
    try:
        cred = SCRAMCredentials.objects.get(username=credname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Credential "{credname}" does not exist'}, status=404)
    try:
        topic = KafkaTopic.objects.get(name=topicname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Topic "{topicname}" does not exist'}, status=404)
    cred_perms = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic)
    if cred_perms.exists():
        cred_perms = [x.operation.name for x in cred_perms]
    else:
        cred_perms = []
    if 'All' in cred_perms:
        if permissions == all_perms:
            return JsonResponse(data={}, status=200)
        cred_perms = ['Read', 'Write', 'Create', 'Delete', 'Alter', 'Describe', 'ClusterAction', 'DescribeConfigs', 'AlterConfigs', 'IdempotentWrite']
        status_code, _ = remove_permission(request.user.username, credname, groupname, topicname, 'All')
        if status_code is not None:
            return JsonResponse(data={'error': status_code}, status=404)
        for perm in cred_perms:
            status_code, _ = add_permission(request.user.username, credname, groupname, topicname, perm)
    for perm in cred_perms:
        if perm not in permissions:
            status_code, _ = remove_permission(request.user.username, credname, groupname, topicname, perm)
            if status_code is not None:
                print(status_code)
                print('Removing {} not found'.format(perm))
                return JsonResponse(data={'error': status_code}, status=404)
    for perm in permissions:
        if perm not in cred_perms:
            status_code, _ = add_permission(request.user.username, credname, groupname, topicname, perm)
            if status_code is not None:
                print(status_code)
                print('Adding {} not found'.format(perm))
                return JsonResponse(data={'error': status_code}, status=404)
    return JsonResponse(data={}, status=200)

def delete_all_credential_permissions(request):
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    groupname = topicname.split('.')[0]
    try:
        cred = SCRAMCredentials.objects.get(username=credname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Credential "{credname}" does not exist'}, status=404)
    try:
        topic = KafkaTopic.objects.get(name=topicname)
    except ObjectDoesNotExist as dne:
        return JsonResponse(data={'error': f'Topic "{topicname}" does not exist'}, status=404)
    cred_perms = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic)
    if cred_perms.exists():
        cred_perms = [x.operation.name for x in cred_perms]
    else:
        cred_perms = []
    for perm in cred_perms:

        status_code, _ = remove_permission(request.user.username, credname, groupname, topicname, perm)
        if status_code is not None:
            return JsonResponse(data={'error': status_code}, status=404)

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

def add_permission(username, credname, groupname, topicname, permission):
    operation = KafkaOperation[permission]
    try:
        user = User.objects.get(username=username)
    except ObjectDoesNotExist as dne:
        return f'User "{username} does not exist', None
    try:
        cred = SCRAMCredentials.objects.get(username=credname)
        if cred.owner.username != user.username and not user.is_staff:
            return f'User "{username}" does not have permissions for credential {credname} and is not staff', None
    except:
        return f'Credential with owner "{username}" and credential name "{credname}"'
    try:
        group = Group.objects.get(name=groupname)
    except ObjectDoesNotExist as dne:
        return f'Group with name "{groupname}" not found', None
    try:
        topic = KafkaTopic.objects.get(owning_group=group, name=topicname)
    except ObjectDoesNotExist as dne:
        return f'Topic with group name "{groupname}"" and topic name "{topicname}"" does not exist', None
    found_one = False
    for perm in GroupKafkaPermission.objects.filter(topic=topic):
        print('{}, {}, {}'.format(perm.principal, perm.topic, perm.operation.name))
    perm = GroupKafkaPermission.objects.filter(topic=topic, operation=KafkaOperation.All)
    if not perm.exists():
        print('All does not exist, trying exact perm')
        perm = GroupKafkaPermission.objects.filter(topic=topic, operation=operation)
        if not perm.exists():
            return f'Topic\'s parent group does not have permission to add {permission}', None
        else:
            CredentialKafkaPermission.objects.create(
                principal=cred,
                parent=perm[0],
                topic=topic,
                operation=operation
            )
            return None, {}
    else:
        print('All exists')
        CredentialKafkaPermission.objects.create(
            principal=cred,
            parent=perm[0],
            topic=topic,
            operation=operation
        )
        return None, {}
    return f'Topic\'s parent group does not have permission to add {permission}', None

def remove_permission(username, credname, groupname, topicname, permission):
    operation = KafkaOperation[permission]
    try:
        user = User.objects.get(username=username)
    except ObjectDoesNotExist as dne:
        return f'User {username} does not exist', None
    try:
        cred = SCRAMCredentials.objects.get(owner=user, username=credname)
    except ObjectDoesNotExist as dne:
        return f'Credential {credname} does not exist', None
    try:
        group = Group.objects.get(name=groupname)
    except ObjectDoesNotExist as dne:
        return f'Group {groupname} does not exist', None
    try:
        topic = KafkaTopic.objects.get(name=topicname)
    except ObjectDoesNotExist as dne:
        return f'Topic {topicname} does not exist', None
    to_delete = CredentialKafkaPermission.objects.filter(
        principal=cred,
        topic=topic,
        operation=operation
    )
    to_delete.delete()
    return None, {}