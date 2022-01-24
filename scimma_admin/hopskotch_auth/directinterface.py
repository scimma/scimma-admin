from .connectioninterface import ConnectionInterface

from .models import *

class DirectInterface(ConnectionInterface):
    def __init__(self):
        pass

    def new_credential(self, username, description):
        try:
            owner = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None

        username = rand_username(owner)
        alphabet = string.ascii_letters + string.digits
        rand_password = "".join(secrets.choice(alphabet) for i in range(32))
        rand_salt = secrets.token_bytes(32)
        creds = SCRAMCredentials.generate(
            owner=owner,
            username=username,
            password=rand_password,
            alg=SCRAMAlgorithm.SHA512,
            salt=rand_salt
        )
        creds.description = description
        creds.save()
        data = {
                'username': creds.username,
                'password': rand_password
            }

        return None, data

    def delete_credential(self, username, credname):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        try:
            credential = SCRAMCredentials.objects.get(username=credname)
        except ObjectDoesNotExist as dne:
            return f'Credential "{credname}" does not exist', None
        if credential.owner.username != username and not user.is_staff:
            return f'Credential can only be deleted by the owning user or a staff member', None
        credential.delete()
        return None, {}
    
    def update_credential(self, username, credname, description):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        try:
            credential = SCRAMCredentials.objects.get(owner=user, username=credname)
        except ObjectDoesNotExist as dne:
            return f'Credentials "{credname}" does not exist', None
        credential.description = description
        credential.save()
        return None, {}

    def get_credential_permissions(self, username, cred_name):
        try:
            user = User.objects.get(username=username)
            cred = SCRAMCredentials.objects.get(owner=user, username=cred_name)
        except ObjectDoesNotExist as dne:
            return 'User or credential not found', None
        perms = CredentialKafkaPermission.objects.filter(principal=cred)
        data = [
            {
                'group': perm.topic.owning_group.name,
                'topic': perm.topic.name,
                'topic_description': perm.topic.description,
                'permission': KafkaOperation(perm.operation).name,
            }
            for perm in perms
        ]
        return None, data

    def add_permission(self, username, credname, groupname, topicname, permission):
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
    
    def get_credential_topic_info(self, username, credname):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        try:
            credential = SCRAMCredentials.objects.get(owner=user, username=credname)
        except ObjectDoesNotExist as dne:
            return f'Credentials "{credname}" does not exist', None
        perms = CredentialKafkaPermission.objects.filter(principal=credential)
        data = [
            {
                'credname': perm.principal.username,
                'groupname': perm.parent.principal.name,
                'topicname': perm.topic.name,
                'description': perm.topic.description,
                'operation': perm.operation.name
            }
        for perm in perms]
        return None, data



    def remove_permission(self, username, credname, groupname, topicname, permission):
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


    def suspend_credential(self, username, credname):
        try:
            user = User.objects.get(username=username)
            credential = SCRAMCredentials.objects.get(owner=user, username=credname)
        except ObjectDoesNotExist as dne:
            return 'User or credential not found', None
        credential.suspended = True
        credential.save()
        return None, {}

    def unsuspend_credential(self, username, credname):
        try:
            user = User.objects.get(username=username)
            credential = SCRAMCredentials.objects.get(owner=user, username=credname)
        except ObjectDoesNotExist as dne:
            return 'User or credential not found', None
        credential.suspended = False
        credential.save()
        return None, {}
    
    def create_group(self, username, group_name, description):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        if not user.is_staff:
            return f'User "{username}" is not staff. Only staff is able to create groups', None
        valid = re.compile("^[a-zA-Z0-9_-]{1,247}$")
        if re.match(valid, group_name) is None:
            return 'Invalid group name', None
        if Group.objects.filter(name=group_name).exists():
            return 'Group already exists', None
        group = Group.objects.create(name=group_name, description=description)
        group.save()

        return None, {}


    def delete_group(self, username, groupname):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        if not user.is_staff:
            return f'User "{username}" is not staff and cannot delete groups', None
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        for member in group.members.all():
            remove_user_group_permissions(member.id, group.id)
        group.delete()
        return None, {}
    
    def add_member_to_group(self, groupname, username, statusname):
        if statusname.lower() != 'owner':
            member_status = MembershipStatus.Member
        else:
            member_status = MembershipStatus.Owner
        try:
            group = Group.objects.get(name=groupname)
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return 'User or group does not exist', None
        cur_membership = GroupMembership.objects.filter(user=user, group=group)
        if cur_membership.exists():
            return f'User "{username}" already exists in  group "{groupname}"', None
        else:
            cur_membership = GroupMembership.objects.create(user=user, group=group, status=member_status)
        return None, {}
    
    def remove_member_from_group(self, groupname, username):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        membership = GroupMembership.objects.filter(user=user, group=group)
        if not membership.exists():
            return f'Group "{groupname}" does not include member "{username}"', None
        membership.delete()
        return None, {}
    
    '''
    def add_topic_to_group(self, groupname, topicname, permission):
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        all_check = GroupKafkaPermission.objects.filter(principal=group, topic=topic, operation=KafkaOperation.All)
        exists_check = GroupKafkaPermission.objects.filter(principal=group, topic=topic, operation=KafkaOperation[permission])
        if all_check.exists() or exists_check.exists():
            return f'Topic "{topicname}" already exists with either "{permission}" or "All"', None
        GroupKafkaPermission.objects.create(principal=group, topic=topic, operation=KafkaOperation[permission])
        return None, {}
    '''
        
        
    '''
    def remove_topic_from_group(self, groupname, topicname, permission):
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        try:
            op = KafkaOperation[permission.capitalize()]
        except Exception as e:
            return f'Permission "{permission}" does not exist', None
        try:
            perm = GroupKafkaPermission.object.get(principal=group, topic=topic, operation=op)
        except ObjectDoesNotExist as dne:
            return f'Permission "{permission}" does not exist in group and topic "{topicname}"', None
        perm.delete()
        return None, {}
    '''

    def create_topic(self, username, group_name, topic_name, description, publicly_readable):
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return 'Group not found', None
        topic = KafkaTopic.objects.create(
        owning_group = group,
        name = group_name + '.' + topic_name,
        publicly_readable = publicly_readable,
        description = description
        )
        group_perm = GroupKafkaPermission.objects.create(
            principal=group,
            topic=topic,
            operation=KafkaOperation.All
        )
        return None, {}


    def delete_topic(self, username, groupname, topicname):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        try:
            topic = KafkaTopic.objects.get(owning_group=group, name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}"" with owning group "{groupname}" does not exist', None
        if not GroupMembership.objects.filter(user=user, group=group, status=MembershipStatus.Owner).exists() or not user.is_staff:
            return 'User cannot delete topic because they are not an owner or a staff member', None
        with transaction.atomic():
            print(GroupKafkaPermission.objects.filter(topic=topic))
            CredentialKafkaPermission.objects.filter(topic=topic).delete()
            GroupKafkaPermission.objects.filter(topic=topic).delete()
        topic.delete()
        return None, {}


    def add_topic_permission(self, username, group_name, topic_name, permission):
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topic_name}" does not exist', None
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return f'Group "{group_name}" does not exist', None
        perm = GroupKafkaPermission.objects.filter(principal=group, topic=topic, operation=KafkaOperation[permission])
        if perm.exists():
            return f'Permission "{permission}" for topic "{topic_name}" already exists', None
        GroupKafkaPermission.objects.create(principal=group, topic=topic, operation=KafkaOperation[permission])
        return None, {}


    def remove_topic_permission(self, username, group_name, topic_name, permission):
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topic_name}" does not exist', None
        try:
            group = Group.objects.get(name=group_name)
        except:
            return f'Group "{group_name}" does not exist', None
        try:
            perm = GroupKafkaPermission.objects.get(principal=group, topic=topic, operation=KafkaOperation[permission])
        except ObjectDoesNotExist as dne:
            return f'Permission "{permission}" for topic "{topic_name}" does not exist', None
        perm.delete()
        return None, {}
        
    
    def get_credential_info(self, username, credname):
        try:
            user = User.objects.get(username=username)
            credential = SCRAMCredentials.objects.get(owner=user, username=credname)
        except ObjectDoesNotExist as dne:
            return 'Could not find user or credential', None
        data = {
            'owner': credential.owner.username,
            'username': credential.username,
            'created_at': credential.created_at,
            'suspended': credential.suspended,
            'description': credential.description
        }
        return None, data

    
    def get_user_credentials(self, username):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        credentials = list(user.scramcredentials_set.all())
        credentials.sort(key=lambda cred: cred.created_at)
        data = [
            {
                'username': cred.username,
                'created_at': cred.created_at.strftime("%Y/%m/%d %H:%M"),
                'description': cred.description
            }
            for cred in credentials
        ]
        return None, data
    
    def get_user_topics(self, username):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        data = []
        memberships = GroupMembership.objects.filter(user=user)
        added_topics = []
        for membership in memberships:
            group = membership.group
            group_permissions = GroupKafkaPermission.objects.filter(principal=group)
            for permission in group_permissions:
                if permission.topic.name not in added_topics:
                    data.append(
                        {
                            'topic': permission.topic.name,
                            'topic_description': permission.topic.description,
                            'accessible_by': group.name
                        }
                    )
                    added_topics.append(permission.topic.name)
        public_topics = KafkaTopic.objects.filter(publicly_readable=True)
        for topic in public_topics:
            if topic.name not in added_topics:
                data.append(
                    {
                        'topic': topic.name,
                        'topic_description': topic.description,
                        'accessible_by': 'public'
                    }
                )
        return None, data
    
    def get_user_groups(self, username):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist'
        groups = user.groupmembership_set.all().select_related('group')
        data = [
            {
                'group_id': group.group.id,
                'group_name': group.group.name,
                'status': MembershipStatus(group.status).name,
                'member_count': group.group.members.count(),
            }
            for group in groups
        ]
        data.sort(key=lambda m: m['group_name'])
        return None, data
    
    def get_all_users(self):
        users = User.objects.all()
        data = [
            {
                'id': user.id,
                'username': user.username,
                'name': '{}, {}'.format(user.last_name, user.first_name),
                'email': user.email
            }
            for user in users
        ]
        return None, data
    
    def clear_all_permissions(self, username, credname):
        try:
            user = User.objects.get(username=username)
            credential = SCRAMCredentials.objects.get(owner=user, username=credname)
        except ObjectDoesNotExist as dne:
            return 'User or credential does not exist', None
        all_creds = CredentialKafkaPermission.objects.filter(principal=credential)
        all_creds.delete()
        return None, {}
    
    def get_user_memberships(self, username):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist'
        memberships = GroupMembership.objects.filter(user=user)
        data = [
            {
                'group_name': membership.group.name,
                'member_status': membership.status.name
            }
        for membership in memberships]
        return None, data
    
    def user_accessible_topics(self, username):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        data = {}

        # first, handle access via group permissions
        user_memberships = GroupMembership.objects.filter(user=user)
        for membership in user_memberships:
            group = membership.group
            group_permissions = GroupKafkaPermission.objects.filter(principal=group)
            for permission in group_permissions:
                if permission.topic.name not in data:
                    data[permission.topic.name] = {
                    'group': permission.principal.name,
                    'topic': permission.topic.name,
                    'group_description': permission.principal.description,
                    'topic_description': permission.topic.description,
                    'accessible_by': permission.principal.name
                }

        # second, collect all public topics
        # By doing this second, if a user has non-public access to a topic which is also public, we will
        # end up labeling it public. This seems more user-friendly for the common case of a user who just
        # wants to read, as it will indicate that specially configuring a credential is not needed.
        public_topics=KafkaTopic.objects.filter(publicly_readable=True)
        for topic in public_topics:
            if topic.name not in data:
                data.append({
                    'group': topic.owning_group.name,
                    'topic': topic.name,
                    'group_description': topic.owning_group.description,
                    'topic_description': topic.description,
                    'accessible_by': 'public'
                })   

        return None, list(data.values())
    
    def get_all_credentials(self):
        credentials = SCRAMCredentials.objects.all()
        data = [
            {
                'username': credential.owner.username,
                'credname': credential.username,
                'created_at': credential.created_at,
                'suspended': credential.suspended,
                'description': credential.description
            }
        for credential in credentials]
        return None, data
    
    def get_all_topics(self):
        topics = KafkaTopic.objects.all()
        data = [
            {
                'owning_group': topic.owning_group.name,
                'name': topic.name,
                'description': topic.description,
                'publicly_readable': topic.publicly_readable
            }
        for topic in topics]
        return None, data
    
    def get_all_groups(self):
        groups = Group.objects.all()

        data = [
            {
                'name': group.name,
                'description': group.description,
                'members': [
                    member.username
                for member in group.members.all()]
            }
        for group in groups]
        return None, data
    
    def get_topic_info(self, groupname, topicname):
        try:
            group = Group.objects.get(name=groupname)
            topic = KafkaTopic.objects.get(owning_group=group, name=f'{groupname}.{topicname}')
        except ObjectDoesNotExist as dne:
            return 'Group or topic does not exist'
        data = {
            'name': topic.name,
            'publicly_readable': topic.publicly_readable,
            'description': topic.description,
        }
        return None, data

    def get_group_info(self, groupname):
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        data = {
            'name': group.name,
            'description': group.description,
            'members': [
                member.username
            for member in group.members.all()
            ]
        }
        return None, data
    
    def get_group_members(self, groupname):
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        data = []
        for member in group.members.all():
            user = User.objects.get(username=member.username)
            membership = GroupMembership.objects.get(group=group, user=user)
            data.append(
                {
                    'username': member.username,
                    'name': '{}, {}'.format(member.last_name, member.first_name),
                    'id': member.id,
                    'email': member.email,
                    'status': membership.status.name
                }
            )
        return None, data
    
    def get_group_topics(self, groupname):
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        topics = KafkaTopic.objects.filter(owning_group=group)
        print([x.owning_group for x in KafkaTopic.objects.all()])
        print(group)
        print(topics)
        data = None
        if topics.exists():
            data = [
                {
                    'topicname': topic.name,
                    'accessible_by': 'Public' if topic.publicly_readable else topic.owning_group.name,
                    'public': topic.publicly_readable,
                    'description': topic.description
                }
            for topic in topics]
            return None, data
        return None, []
    
    def add_group_to_topic(self, topicname, groupname, permissionname):
        permission = KafkaOperation[permissionname]
        try:
            group = Group.objects.get(name=groupname)
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return 'Either group or topic not found', None
        if GroupKafkaPermission.objects.filter(principal=group, topic=topic, operation=permission).exists():
            return f'Permission({permissionname}) already exists for {groupname}.{topicname}', None
        perm = GroupKafkaPermission.objects.create(principal=group, topic=topic, operation=permission)
        return None, {}
    
    def remove_group_from_topic(self, topicname, groupname, permissionname):
        permission = KafkaOperation[permissionname]
        try:
            group = Group.objects.get(name=groupname)
            topic = KafkaTopic.objects.get(name=topicname)
            perm = GroupKafkaPermission.objects.get(principal=group, topic=topic, operation=permission)
        except ObjectDoesNotExist as dne:
            return 'Group, topic or permission does not exist', None
        perm.delete()
        return None, {}
    
    def is_user_admin(self, username):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist'
        return None, {'is_admin': user.is_staff}
    
    def get_all_user_permissions(self, username):
        return 'This function is not implemented', None
    
    def get_groups_by_topic(self, topicname):
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic with name "{topicname}" does not exist'
        permissions = GroupKafkaPermission.objects.filter(topic=topic)
        data = [
            {
                'group': perm.principal.name,
                'operation': perm.operation.name,
                'topic_name': perm.topic.name,
                'can_edit': False if perm.principal.name == topic.owning_group.name else True
            }
        for perm in permissions]
        return None, data
    
    def change_user_group_status(self, username, groupname, statusname):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        if statusname.lower() == 'owner':
            permission = MembershipStatus.Owner
        elif statusname.lower() == 'member':
            permission = MembershipStatus.Member
        else:
            return f'Permission with name "{statusname}" does not exist', None
        try:
            membership = GroupMembership.objects.get(user=user, group=group)
        except ObjectDoesNotExist as dne:
            return f'User does not have a membership to the specified group', None
        membership.status = permission
        membership.save()
        return None, {}
    
    def get_group_permissions(self, groupname, topicname):
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        all_perms = GroupKafkaPermission.objects.filter(principal=group, topic=topic)
        print(all_perms)
        if all_perms.exists():
            results = [
                {
                    'groupname': perm.principal.name,
                    'groupdescription': perm.principal.description,
                    'topicname': perm.topic.name,
                    'topicdescription': perm.topic.description,
                    'operation': perm.operation.name,
                }
            for perm in all_perms]
            return None, results
        return None, [] 
    
    def modify_group_description(self, groupname, description):
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        group.description = description
        group.save()
        return None, {}
    
    def get_topic_permissions(self, groupname, topicname):
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        all_perms = GroupKafkaPermission.objects.filter(principal=group, topic=topic)
        data = []
        for perm in all_perms:
            data.append(KafkaOperation(perm.operation).name)
        
        return None, data
    
    def add_topic_to_group(self, groupname, topicname):
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        exists_check = GroupKafkaPermission.objects.filter(principal=group, topic=topic)
        if exists_check.exists():
            return f'There is already a permission added for group "{groupname}" and topic "{topicname}"', None
        GroupKafkaPermission.objects.create(principal=group, topic=topic, operation=KafkaOperation['All'])
        return None, {}

    def remove_topic_from_group(self, groupname, topicname):
        try:
            group = Group.objects.get(name=groupname)
        except ObjectDoesNotExist as dne:
            return f'Group "{groupname}" does not exist', None
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        all_perms = GroupKafkaPermission.objects.filter(principal=group, topic=topic)
        with transaction.atomic():
            all_perms.delete()
        return None, {}
    
    def add_permission_to_group(self, credname, topicname, operation):
        try:
            cred = SCRAMCredentials.objects.get(username=credname)
        except ObjectDoesNotExist as dne:
            return f'Credential "{credname}" does not exist', None
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        op = KafkaOperation[operation]
        op_check = GroupKafkaPermission.objects.filter(topic=topic, operation=op)
        if not op_check.exists():
            return f'You cannot add {operation} to {credname} since it lacks the permission', None
        cred_check = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic, operation=op)
        if cred_check.exists():
            return f'Credential "{credname}" already has permission "{operation}"', None
        CredentialKafkaPermission.objects.create(
            principal=cred,
            parent=op_check.first(),
            topic=topic,
            operation=op
        )
        return None, {}
    
    def remove_permission_from_group(self, credname, topicname, operation):
        try:
            cred = SCRAMCredentials.objects.get(username=credname)
        except ObjectDoesNotExist as dne:
            return f'Credential "{credname}" does not exist', None
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        op = KafkaOperation[operation]
        cred_check = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic, operation=op)
        if cred_check.exists():
            cred_check.delete()
            return None, {}
        return f'Permission "{operation}" for topic "{topicname}" using credential "{credname}" does not exist', None
    
    def get_available_credential_permissions(self, username):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return f'User "{username}" does not exist', None
        possible_permissions = []
        for membership in user.groupmembership_set.all():
            group = membership.group
            group_permissions = GroupKafkaPermission.objects.filter(principal=group).select_related('topic')
            for permission in group_permissions:
                if permission.operation==KafkaOperation.All:
                    for subpermission in KafkaOperation.__members__.items():
                        possible_permissions.append({
                            'group': permission.principal.name,
                            'topic_id': permission.topic.id,
                            'topic': permission.topic.name,
                            'group_description': permission.principal.description,
                            'topic_description': permission.topic.description,
                            'operation': subpermission[1].name
                        })
                        #possible_permissions.append((permission.topic.name,permission.topic.description, permission.principal.name, subpermission[1].name))
                else:
                    possible_permissions.append({
                        'group': permission.principal.name,
                        'topic_id': permission.topic.id,
                        'topic': permission.topic.name,
                        'group_description': permission.principal.description,
                        'topic_description': permission.topic.description,
                        'operation': permission.operation.name
                    })
                    #possible_permissions.append((permission.topic.name,permission.operation.name))
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
            return p1['topic_id'] == p2['topic_id'] and p1['operation'] == p2['operation']
            #return p1[0] == p2[0] and p1[-1] == p2[-1]

        # remove adjacent (practical) duplicates which have different permission IDs
        dedup = []
        last = None
        for p in possible_permissions:
            if last is None or not equivalent(last,p):
                dedup.append(p)
                last=p
        
        return None, dedup
    
    def get_permissions_on_credential(self, credname, topicname):
        try:
            cred = SCRAMCredentials.objects.get(username=credname)
        except ObjectDoesNotExist as dne:
            return f'Credential "{credname}" does not exist', None
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        cred_perms = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic)
        print('------------------------------------------------------------------------------------')
        print([x.operation.name for x in cred_perms])
        print('------------------------------------------------------------------------------------')
        if cred_perms.exists():
            return None, [x.operation.name for x in cred_perms]
        return None, []
    
    def get_topic_groups(self, topicname):
        try:
            topic = KafkaTopic.objects.get(name=topicname)
        except ObjectDoesNotExist as dne:
            return f'Topic "{topicname}" does not exist', None
        all_memberships = GroupKafkaPermission.objects.filter(topic=topic)
        if all_memberships.exists():
            cleaned_memberships = []
            for x in all_memberships:
                if x.principal.name not in cleaned_memberships:
                    cleaned_memberships.append(x.principal.name)
            return None, cleaned_memberships
        return None, []