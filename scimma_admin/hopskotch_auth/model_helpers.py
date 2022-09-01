from django.core.exceptions import ObjectDoesNotExist

# Create your views here.
import string
import secrets
import re

from .models import *

# All helpers return a tuple of the form: (error_message, data)
# In the case of an error then "data" will be none, in the case of success then "error_message" will be None
def get_users():
    users = User.objects.all()
    data = [
            {
                'id': str(user.id),
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email
            }
        for user in users]
    return None, data

def get_user_info(username):
    try:
        user = User.objects.get(username=username)
    except ObjectDoesNotExist as dne:
        return f'User "{username}" does not exist', None
    data = {
        'id': str(user.id),
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'email': user.email,
        'staff': user.is_staff,
    }

    return None, data

def get_user_credentials(username):
    try:
        user = User.objects.get(username=username)
    except ObjectDoesNotExist as dne:
        return f'User "{username}" does not exist', None
    credentials = SCRAMCredentials.objects.filter(owner=user)
    if not credentials.exists():
        return f'User "{username}" does not own any credentials'
    data = [
        {
            'username': cred.username,
            'created_at': cred.created_at.strftime("%Y/%m/%d %H:%M"),
            'description': cred.description,
        }
    for cred in credentials]
    return None, data

def create_user_credential(username, description=''):
    try:
        user = User.objects.get(username=username)
    except ObjectDoesNotExist as dne:
        return f'User "{username}" does not exist', None
    username = rand_username(user)
    alphabet = string.ascii_letters + string.digits
    rand_password = "".join(secrets.choice(alphabet) for i in range(32))
    rand_salt = secrets.token_bytes(32)
    cred = SCRAMCredentials.generate(
        owner=user,
        username=username,
        password=rand_password,
        alg=SCRAMAlgorithm.SHA512,
        salt=rand_salt
    )
    cred.description = description
    cred.save()
    data = {
        'credname': username,
        'password': rand_password,
    }
    return None, data

def get_user_credential_information(username, credname):
    try:
        user = User.objects.get(username=username)
    except:
        return f'User "{username}" does not exist', None
    try:
        credential = SCRAMCredentials.objects.get(owner=user, username=credname)
    except:
        return f'Credential "{credname}" does not exist', None
    data = {
        'owner': credential.owner.username,
        'credname': credential.username,
        'created_at': credential.created_at,
        'suspended': credential.suspended,
        'description': credential.description,
    }
    return None, data

def delete_user_credential(username, credname):
    try:
        user = User.objects.get(username=username)
    except:
        return f'User "{username}" does not exist', None
    try:
        credential = SCRAMCredentials.objects.get(owner=user, username=credname)
    except:
        return f'Credential "{credname}" does not exist', None
    
    credential.delete()
    return None, None

def change_user_credential_description(username, credname, description):
    try:
        user = User.objects.get(username=username)
    except:
        return f'User "{username}" does not exist', None
    try:
        credential = SCRAMCredentials.objects.get(owner=user, username=credname)
    except:
        return f'Credential "{credname}" does not exist', None
    credential.description = description
    credential.save()
    return None, None

def get_user_groups(username):
    try:
        user = User.objects.get(username=username)
    except:
        return f'User "{username}" does not exist', None
    memberships = GroupMembership.objects.filter(user=user)
    data = [
        {
            'groupname': membership.group.name,
            'status': membership.status.name,
        }
    for membership in memberships]

    return None, data

def get_user_topics(username):
    try:
        user = User.objects.get(username=username)
    except:
        return f'User "{username}" does not exist', None
    data = []
    user_memberships = GroupMembership.objects.filter(user=user)
    for membership in user_memberships:
        group = membership.group
        group_permissions = GroupKafkaPermission.objects.filter(principal=group).select_related('topic')
        for permission in group_permissions:
            data.append({
                'group': permission.principal.name,
                'topic': permission.topic.name,
                'group_description': permission.principal.description,
                'topic_description': permission.topic.description,
                'accessible_by': permission.principal.name
            })
    public_topics = KafkaTopic.objects.filter(publicly_readable=True)
    for topic in public_topics:
        data.append({
            'group': topic.owning_group.name,
            'topic': topic.name,
            'group_description': topic.owning_group.description,
            'topic_description': topic.description,
            'accessible_by': 'public'
        })
    if len(data) == 0:
        return f'User "{username}" has access to no topics', None
    return None, data