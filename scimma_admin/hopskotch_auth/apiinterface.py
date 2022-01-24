from .connectioninterface import ConnectionInterface
import requests
import json
from .models import *

class ApiInterface(ConnectionInterface):
    def __init__(self):
        pass

    def new_credential(self, username, description):
        data={
            'description':description
            }

        r = requests.post(f'http://localhost:5000/hopauth/users/{username}/credentials', data=data)
        response_data = r.json()

        if r.status_code == 201:
            return (r.status_code, response_data)
        return ('Could not save data', {})

    def delete_credential(self, username, credname):
        r = requests.delete(f'http://localhost:5000/hopauth/users/{username}/credentials/{credname}')

        if r.status_code == 201:
            return (r.status_code, {})
        return ('Could not delete data', {})
    
    def update_credential(self, username, credname, description):
        data = {
            'description': description
        }
        r = requests.put(f'http://localhost:5000/hopauth/users/{username}/credentials/{credname}', data=data)
        return r.status_code, {}

    def get_credential_permissions(self, username, cred_name):
        data = {
            'username': username,
            'cred_name': cred_name
        }
        r = requests.get(f'http://localhost:5000/hopauth/get_credential_permissions/{username}&{cred_name}', data=data)
        response_data = r.json()
        if r.status_code == 200:
            return (r.status_code, response_data)
        return ('Could not get credential data', {})



    def add_permission(self, username, cred_name, group, topic, permission):
        data = {
            'username': username,
            'cred_name': cred_name,
            'group': group,
            'topic': topic,
            'permission': permission,
        }
        r = requests.post('http://localhost:5000/hopauth/add_credential_permission/', data=data)
        return r.status_code, {}


    def remove_permission(self, username, cred_name, group, topic, permission):
        try:
            credential = SCRAMCredentials.objects.get(username[cred_name])
        except ObjectDoesNotExist as dne:
            print('{} in remove_permission'.format(dne))
            return 404, {}
        if username != credential.owner:
            print('User is not the owner of the credential')
            return 403, {}
        try:
            perm = CredentialKafkaPermission.objects.get(id=permission)
        except ObjectDoesNotExist as dne:
            print('{} in remove_permission'.format(dne))
            return 403, {}


    def suspend_credential(self, username, cred_name):
        r = requests.put(f'http://localhost:5000/hopauth/users/{username}/credentials/{cred_name}/suspend')
        return r.status_code, {}

    def unsuspend_credential(self, username, cred_name):
        r = requests.put(f'http://localhost:5000/hopauth/users/{username}/credentials/{cred_name}/unsuspend')
        return r.status_code, {}
    
    def create_group(self, username, group_name, description):
        data = {
            'group_name': group_name,
            'description': description,
        }
        r = requests.post('http://localhost:5000/hopauth/groups', data=data)
        if r.status_code == 201:
            return (r.status_code, {})
        return ('Could not create group', {})


    def delete_group(self, username, group_name):
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            print('Group does not exist in delete_group')
            return 404, {}
        group.delete()
        return 200, {}
    
    def add_member_to_group(self, groupname, username, statusname):
        data = {
            'username': username,
            'member_status': statusname,
        }
        r = requests.post(f'http://localhost:5000/hopauth/groups/{groupname}/members', data=data)
        return (r.status_code, r.text) if r.status_code != 200 else (r.status_code, {})

    def add_topic_to_group(self, username, group_name, topic_name):
        pass

    def remove_topic_from_group(self, username, group_name, topic_name):
        pass

    def create_topic(self, username, group_name, topic_name, description, publicly_readable):
        data = {
            'topic_name': topic_name,
            'description': description,
            'publicly_readable': publicly_readable
        }
        r = requests.post(f'http://localhost:5000/hopauth/groups/{group_name}/topics', data=data)
        return r.status_code, {}


    def delete_topic(self, username, group_name, topic_name):
        try:
            topic = KafkaTopic.objects.get(name=topic_name, owning_group=group_name)
        except ObjectDoesNotExist as dne:
            print('Topic does not exist in delete_topic')
            return 403, {}
        if not GroupMembership.objects.filter(
            models.Q(status=MembershipStatus.Owner),
            user_id=username,
            name=group_name
        ).exists():
            print('User does not own group in delete_topic')
            return 404, {}
        CredentialKafkaPermission.objects.filter(topic=topic).delete()
        GroupKafkaPermission.objects.filter(topic=topic).delete()
        topic.delete()
        return 200, {}


    def add_topic_permission(self, username, topic_name, permission):
        pass


    def remove_topic_permission(self, username, topic_name, permission):
        
        CredentialKafkaPermission.objects.filter(topic=topic_name)
        GroupKafkaPermission.object.filter(topic=topic_name)


    def get_all_user_permissions(self, username):
        data = {
            'username': username
        }
        r = requests.get(f'http://localhost:5000/hopauth/get_topics_by_user/{username}')
        if r.status_code == 200:
            return (r.status_code)
        return ('Could not retrieve data')
    
    def get_credential_info(self, username, credname):
        r = requests.get(f'http://localhost:5000/hopauth/users/{username}/credentials/{credname}')
        if r.status_code != 200:
            return r.status_code, {}
        return r.status_code, r.json()

    
    def get_user_credentials(self, username):
        r = requests.get(f'http://localhost:5000/hopauth/get_user_credentials/{username}')
        if r.status_code == 200:
            return r.status_code, r.json()
        return r.status_code, 'Could not retrieve data'
    
    def get_user_topics(self, username):
        r = requests.get(f'http://localhost:5000/hopauth/get_user_topics/{username}')
        if r.status_code == 200:
            return r.status_code, r.json()
        return r.status_code, 'Could not retrieve data'
    
    def get_user_groups(self, username):
        r = requests.get(f'http://localhost:5000/hopauth/get_user_groups/{username}')
        if r.status_code == 200:
            return r.status_code, r.json()
        return r.status_code, 'Could not retrieve data'
    
    def get_all_users(self):
        r = requests.get('http://localhost:5000/hopauth/get_all_users/')
        if r.status_code == 200:
            return r.status_code, r.json()
        return r.status_code, 'Could not get users'
    
    def clear_all_permissions(self, username, credname):
        r = requests.post(f'http://localhost:5000/hopauth/users/{username}/credentials/{credname}/clear')
        if r.status_code == 200:
            return (r.status_code, None)
        return r.status_code, 'Could not clear permissions'
    
    def get_user_memberships(self, username):
        r = requests.post(f'http://localhost:5000/hopauth/users/{username}/groups')
        if r.status_code == 404:
            return r.status_code, r.text
        data = r.json()
        return r.status_code, data
    
    def user_accessible_topics(self, username):
        r = requests.get(f'http://localhost:5000/hopauth/users/{username}/topics')
        if r.status_code != 200:
            return r.status_code, {}
        data = r.json()
        return r.status_code, data
    
    def get_all_credentials(self):
        r = requests.get('http://localhost:5000/hopauth/credentials')
        if r.status_code != 200:
            return r.status_code, {}
        return r.status_code, r.json()
    
    def get_all_topics(self):
        r = requests.get('http://localhost:5000/hopauth/topics')
        if r.status_code != 200:
            return r.status_code, {}
        return r.status_code, r.json()
    
    def get_all_groups(self):
        r = requests.get('http://localhost:5000/hopauth/groups')
        if r.status_code != 200:
            return r.status_code, {}
        return r.status_code, r.json()
    
    def get_topic_info(self, groupname, topicname):
        r = requests.get(f'http://localhost:5000/hopauth/groups/{groupname}/topics/{topicname}')
        if r.status_code != 200:
            return r.status_code, {}
        return r.status_code, r.json()

    def get_group_info(self, groupname):
        r = requests.get(f'http://localhost:5000/hopauth/groups/{groupname}')
        if r.status_code != 200:
            return r.status_code, {}
        return r.status_code, r.json()
    
    def get_group_members(self, groupname):
        r = requests.get(f'http://localhost:5000/hopauth/groups/{groupname}/members')
        if r.status_code != 200:
            return r.status_code, {}
        return r.status_code, r.json()
    
    def get_group_topics(self, groupname):
        r = requests.get(f'http://localhost:5000/hopauth/groups/{groupname}/topics')
        if r.status_code != 200:
            return r.status_code, {}
        return r.status_code, r.json()
    
    def add_group_to_topic(self, topicname, groupname, permission):
        data = {
            'groupname': groupname,
            'permission': permission
        }
        topicname = groupname + '.' + topicname
        r = requests.post(f'http://localhost:5000/hopauth/topics/{topicname}/groups', data=data)
        return r.status_code, {}
    
    def remove_group_from_topic(self, topicname, groupname, permission):
        data = {
            'groupname': groupname,
            'permission': permission
        }
        topicname = groupname + '.' + topicname
        r = requests.delete(f'http://localhost:5000/hopauth/topics/{topicname}/groups', data=data)
        return r.status_code, {}
    
    def is_user_admin(self, username):
        r = requests.get(f'http://localhost:5000/hopauth/users/{username}/admin')
        if r.status_code != 200:
            return r.status_code, {}
        return r.status_code, r.json()