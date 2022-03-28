from django.http import JsonResponse
from django.contrib.auth.decorators import login_required

from .models import *
from .directinterface import DirectInterface
from .views import log_request, json_with_error, AuthenticatedHttpRequest

engine = DirectInterface()

# TODO: this appears misnamed as it does not modify data, only fetches it
@login_required
def add_all_credential_permission(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, "fetch all possible permissions for credential "
                f"{request.POST.get('credname','<unset>')}")
    credname = request.POST['credname']
    topicname = request.POST['topicname']

    topic_result = engine.get_topic(topicname)
    if not topic_result:
        return json_with_error(request, "add_all_credential_permission", topic_result.err(), 400)
    topic = topic_result.ok()

    perms_result = engine.get_available_credential_permissions(request.user, topic)
    if not perms_result:
        return json_with_error(request, "add_all_credential_permission", perms_result.err(), 400)
    perms = perms_result.ok()

    possible_permissions = []
    for perm in perms:
        if perm[0].operation not in possible_permissions:
            possible_permissions.append(perm[0].operation)
    # TODO: Probably some result should be returned?
    return JsonResponse(data={}, status=200)

# TODO: the name and implementation of this function are inconsistent: does it get (accessible)
# topics for the credential (really the user), or possible permissions relating to one topic?
@login_required
def get_available_credential_topics(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, "fetch accessible topics for credential "
                f"{request.POST.get('credname','<unset>')}")
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    possible_perms = []
    cred_perms = []

    topic_result = engine.get_topic(topicname)
    if not topic_result:
        return json_with_error(request, "get_available_credential_topics", topic_result.err(), 400)
    topic = topic_result.ok()

    perms_result = engine.get_available_credential_permissions(request.user, topic)
    if not perms_result:
        return json_with_error(request, "get_available_credential_topics", perms_result.err(), 400)
    perms = perms_result.ok()
    for permission in perms:
        possible_perms.append({
            'topic_id': permission[0].topic.id,
            'topic': permission[0].topic.name,
            'description': permission[0].topic.description,
            'access_via': permission[0].principal.name,
            'operation': permission[1],
        })

    cred_perms_result = engine.get_credential_permissions_for_topic(credname, topicname)
    if not cred_perms_result:
        return json_with_error(request, "get_available_credential_topics", cred_perms_result.err(), 400)
    cred_perms = cred_perms_result.ok()

    return JsonResponse(data={'data': possible_perms,
                              'cred_data': [x.operation.name for x in cred_perms]},
                        status=200)

@login_required
def get_group_permissions(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, "fetch all permissions held by group {request.POST.get('groupname','<unset>')}"
                f" for topic {request.POST.get('topicname','<unset>')}")
    log_request(request, "fetch accessible topics for credential "
                f"{request.POST.get('credname','<unset>')}")
    topicname = request.POST['topicname']
    groupname = request.POST['groupname']

    group_perms_result = engine.get_group_permissions_for_topic(groupname, topicname)
    if not group_perms_result:
        return json_with_error(request, "get_group_permissions", group_perms_result.err(), 400)
    group_perms = group_perms_result.ok()

    perms = [x.operation.name for x in group_perms]
    return JsonResponse(data={'permissions': perms}, status=200)

# TODO: This scheme is very inefficient, and makes precise logging difficult.
# It would be much better to separately specify permissions to add and to remove.
@login_required
def bulk_set_topic_permissions(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"change permissions held by group {request.POST.get('groupname','<unset>')}"
                f" for topic {request.POST.get('topicname','<unset>')}")
    groupname = request.POST['groupname']
    topicname = request.POST['topicname']
    permissions = set(request.POST.getlist('permissions'))

    perms_result = engine.get_group_permissions_for_topic(groupname, topicname)
    if not perms_result:
        return json_with_error(request, "bulk_set_topic_permissions", perms_result.err(), 400)
    existing = perms_result.ok()

    # If the group already has All permission, either it matches the set of new permissions or needs to be removed
    if any(p.operation == KafkaOperation.All for p in existing):
        if "All" in permissions:
            if len(permissions) > 1:
                # it is a logical error to combine any other permission with All
                return json_with_error(request, "bulk_set_topic_permissions", "Logically inconsistent request: "
                                       "It does not make sense to combine specific permissions with All", 400)
            # otherwise, there's nothing to do
            return JsonResponse(data={}, status=200)
        else:
            # if a subset of permissions are specified, All must first be removed
            remove_result = engine.remove_group_topic_permission(request.user, groupname, topicname, KafkaOperation.All)
            if not remove_result:
                return json_with_error(request, "bulk_set_topic_permissions", remove_result.err(), 400)
    # Add all specified permissions which aren't already present
    for perm_name in permissions:
        expected_perm = KafkaOperation[perm_name]
        if not any(p.operation == expected_perm for p in existing):
            # Need to add
            add_result = engine.add_group_topic_permission(request.user, groupname, topicname, expected_perm)
            if not remove_result:
                return json_with_error(request, "bulk_set_topic_permissions", add_result.err(), 400)
    # Remove all existing permissions which are not specified
    for existing_perm in existing:
        if str(existing_perm.operation) not in permissions:
            # Need to remove
            remove_result = engine.remove_group_topic_permission(request.user, groupname, topicname, existing_perm.operation)
            if not remove_result:
                return json_with_error(request, "bulk_set_topic_permissions", remove_result.err(), 400)

    return JsonResponse(data={}, status=200)

# TODO: duplicate of bulk_set_topic_permissions?
'''
@login_required
def bulk_set_group_permissions(request: AuthenticatedHttpRequest) -> JsonResponse:
    topicname = request.POST['topicname']
    groupname = request.POST['groupname']
    new_perms = request.POST.getlist('permissions')
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
'''

@login_required
def toggle_suspend_credential(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"change credential {request.POST.get('credname','<unset>')} suspension")
    credname = request.POST['credname']

    cred_result = engine.get_credential(request.user, credname)
    if not cred_result:
        return json_with_error(request, "toggle_suspend_credential", cred_result.err(), 400)
    cred = cred_result.ok()

    if request.user != cred.owner and not request.user.is_staff:
        return json_with_error(request, "toggle_suspend_credential", 'You must either be the owner or a staff member', 403)

    result = engine.toggle_credential_suspension(request.user, cred)
    if not result:
        return json_with_error(request, "toggle_suspend_credential", result.err(), 400)
    return JsonResponse(data={'suspended': result.ok()}, status=200)

@login_required
def delete_credential(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"delete credential {request.POST.get('credname','<unset>')}")
    delete_result = engine.delete_credential(request.user.username, request.POST['credname'])
    if not delete_result:
        return json_with_error(request, "delete_credential", delete_result.err(), 400)
    return JsonResponse(data={}, status=200)

@login_required
def delete_topic(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"delete topic {request.POST.get('topicname','<unset>')}")
    delete_result = engine.delete_topic(request.user.username, request.POST['topicname'])
    if not delete_result:
        return json_with_error(request, "delete_topic", delete_result.err(), 400)
    return JsonResponse(data={}, status=200)

@login_required
def delete_group(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"delete group {request.POST.get('groupname','<unset>')}")
    delete_result = engine.delete_group(request.user.username, request.POST['groupname'])
    if not delete_result:
        return json_with_error(request, "delete_group", delete_result.err(), 400)
    return JsonResponse(data={}, status=200)

# TODO: This has the same issues as bulk_set_topic_permissions
# This is additionally problematic, because, unlike the old design, it does not track a likely viable
# group permission from which each credential permission can be derived, forcing an expensive computation
# to try to find a satisfactory one.
@login_required
def bulk_set_credential_permissions(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"change permissions held by credential {request.POST.get('credname','<unset>')}"
                f" for topic {request.POST.get('topicname','<unset>')}")
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    groupname = topicname.split('.')[0]
    permissions = set(request.POST.getlist('permissions'))

    if "All" in permissions:
        if len(permissions) > 1:
            # it is a logical error to combine any other permission with All
            return json_with_error(request, "bulk_set_credential_permissions", "Logically inconsistent request: "
                                   "It does not make sense to combine specific permissions with All", 400)

    perms_result = engine.get_credential_permissions_for_topic(credname, topicname)
    if not perms_result:
        return json_with_error(request, "bulk_set_credential_permissions", perms_result.err(), 400)
    existing = perms_result.ok()

    # If the credential already has All permission, either it matches the set of new permissions or needs to be removed
    if any(p.operation == KafkaOperation.All for p in existing):
        if "All" in permissions:
            # otherwise, there's nothing to do
            return JsonResponse(data={}, status=200)
        else:
            # if a subset of permissions are specified, All must first be removed
            remove_result = engine.remove_credential_permission(request.user, credname, topicname, KafkaOperation.All)
            if not remove_result:
                return json_with_error(request, "bulk_set_credential_permissions", remove_result.err(), 400)
    # Add all specified permissions which aren't already present
    for perm_name in permissions:
        expected_perm = KafkaOperation[perm_name]
        if not any(p.operation == expected_perm for p in existing):
            # Need to add
            add_result = engine.add_credential_permission(request.user, credname, topicname, expected_perm)
            if not add_result:
                return json_with_error(request, "bulk_set_credential_permissions", add_result.err(), 400)
    # Remove all existing permissions which are not specified
    for existing_perm in existing:
        if str(existing_perm.operation) not in permissions:
            # Need to remove
            remove_result = engine.remove_credential_permission(request.user, credname, topicname, existing_perm.operation)
            if not remove_result:
                return json_with_error(request, "bulk_set_credential_permissions", remove_result.err(), 400)

    return JsonResponse(data={}, status=200)

# TODO: duplicate ?
'''
@login_required
def bulk_set_credential_permissions(request: AuthenticatedHttpRequest) -> JsonResponse:
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
'''

# TODO: Why is this specific to a topic? When is this operation useful?
@login_required
def delete_all_credential_permissions(request: AuthenticatedHttpRequest) -> JsonResponse:
    log_request(request, f"delete all permissions held by credential {request.POST.get('credname','<unset>')}"
                f" for topic {request.POST.get('topicname','<unset>')}")
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    perms_result = engine.get_credential_permissions_for_topic(credname, topicname)
    if not perms_result:
        return json_with_error(request, "delete_all_credential_permissions", perms_result.err(), 400)
    for perm in perms_result.ok():
        remove_result = engine.remove_credential_permission(request.user, credname, topicname, perm.operation)
        if not remove_result:
            return json_with_error(request, "delete_all_credential_permissions", remove_result.err(), 400)
    return JsonResponse(data={}, status=200)

# TODO: duplicate ?
'''
@login_required
def delete_all_credential_permissions(request: AuthenticatedHttpRequest) -> JsonResponse:
    credname = request.POST['credname']
    topicname = request.POST['topicname']
    perms_result = engine.get_credential_permissions_for_topic(credname, topicname)
    if not perms_result:
        return json_with_error(request, "delete_all_credential_permissions", perms_result.err(), 400)
    for perm in perms_result.ok():
        remove_result = engine.remove_credential_permission(request.user, credname, topicname, perm.operation)
        if not remove_result:
            return json_with_error(request, "delete_all_credential_permissions", remove_result.err(), 400)
    return JsonResponse(data={}, status=200)
'''

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

# Unused?
'''
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
'''
