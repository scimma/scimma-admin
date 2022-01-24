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
