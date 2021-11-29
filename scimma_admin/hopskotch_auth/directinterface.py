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
            print(f'User "{username}" does not exist'), None
        try:
            credential = SCRAMCredentials.objects.get(owner=user, username=credname)
        except ObjectDoesNotExist as dne:
            print(f'Credentials "{credname}" does not exist')
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
                'permission_type': KafkaOperation(perm.operation).name,
            }
            for perm in perms
        ]
        return None, data

    def add_permission(self, username, credname, groupname, topicname, permission):
        if permission.lower() == 'read':
            operation = KafkaOperation.Read
        elif permission.lower() == 'write':
            operation = KafkaOperation.Write
        else:
            return f'Permission name "{permission}" not valid', None
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
            topic = KafkaTopic.objects.get(owning_group=group, name='.'.join([groupname, topicname]))
        except ObjectDoesNotExist as dne:
            return f'Topic with group name "{groupname}"" and topic name "{topicname}"" does not exist', None
        found_one = False
        perm = GroupKafkaPermission.objects.filter(principal=group, topic=topic, operation=KafkaOperation.All)
        if not perm.exists():
            perm = GroupKafkaPermission.objects.filter(principal=group, topic=topic, operation=operation)
            if not perm.exists():
                return f'Topic\'s parent group does not have permission to add {permission}', None
        
        all_perm = GroupKafkaPermission.objects.filter(principal=group, topic=topic, operation=KafkaOperation.All)
        if all_perm.exists():
            if not CredentialKafkaPermission.objects.filter(principal=cred, topic=topic, operation=operation).exists():
                CredentialKafkaPermission.objects.create(
                    principal=cred,
                    parent=all_perm[0],
                    topic=topic,
                    operation=operation
                )
                return None, {}
            else:
                return f'Credential {credname} already has permission "{permission}" from topic {topicname}', None
        
        op_perm = GroupKafkaPermission.objects.filter(principal=group, topic=topic, operation=operation)
        if op_perm.exists():
            if not CredentialKafkaPermission.objects.filter(principal=cred, topic=topic, operation=operation).exists():
                CredentialKafkaPermission.objects.create(
                    principal=cred,
                    parent=all_perm[0],
                    topic=topic,
                    operation=operation
                )
                return None, {}
            else:
                return f'Credential {credname} already has permission "{permission}" for topic {topicname}', None
        return f'Topic\'s parent group does not have permission to add {permission}', None
    
    def get_credential_topic_info(self, username, credname):
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            print(f'User "{username}" does not exist'), None
        try:
            credential = SCRAMCredentials.objects.get(owner=user, username=credname)
        except ObjectDoesNotExist as dne:
            print(f'Credentials "{credname}" does not exist')
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
        if permission.lower() == 'read':
            operation = KafkaOperation.Read
        elif permission.lower() == 'write':
            operation = KafkaOperation.Write
        else:
            return f'Permission name "{permission}" not valid', None
        try:
            user = User.objects.get(username=username)
            cred = SCRAMCredentials.objects.get(owner=user, username=credname)
            group = Group.objects.get(name=groupname)
            topic = KafkaTopic.objects.get(owning_group=group, name='.'.join([groupname, topicname]))
            to_delete = CredentialKafkaPermission.objects.filter(
                principal=cred,
                topic=topic,
                operation=operation
            )
        except ObjectDoesNotExist as dne:
            return f'In add_permission, a bad name was passed in', None
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

    def unsuspend_credential(self, username, cred_name):
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
        membership = GroupMembership.objects.get()

    def add_topic_to_group(self, username, group_name, topic_name):
        pass

    def remove_topic_from_group(self, username, group_name, topic_name):
        pass

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
            CredentialKafkaPermission.objects.filter(topic=topic).delete()
            GroupKafkaPermission.objects.filter(topic=topic).delete()
        topic.delete()
        return None, {}


    def add_topic_permission(self, username, topic_name, permission):
        pass


    def remove_topic_permission(self, username, topic_name, permission):
        
        CredentialKafkaPermission.objects.filter(topic=topic_name)
        GroupKafkaPermission.object.filter(topic=topic_name)
    
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
            group_permissions = GroupKafkaPermission.objects.filter(principal=group).select_related('topic')
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
        data = []

        # first, handle access via group permissions
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

        # second, collect all public topics
        # By doing this second, if a user has non-public access to a topic which is also public, we will
        # end up labeling it public. This seems more user-friendly for the common case of a user who just
        # wants to read, as it will indicate that specially configuring a credential is not needed.
        public_topics=KafkaTopic.objects.filter(publicly_readable=True)
        for topic in public_topics:
            data.append({
                'group': topic.owning_group.name,
                'topic': topic.name,
                'group_description': topic.owning_group.description,
                'topic_description': topic.description,
                'accessible_by': 'public'
            })
        

        return None, data
    
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
        data = None
        if topics.exists():
            data = [
                {
                    'name': topic.name,
                    'accessible_by': 'Public' if topic.publicly_readable else topic.owning_group.name,
                    'public': topic.publicly_readable,
                    'description': topic.description
                }
            for topic in topics]
        return None, data
    
    def add_group_to_topic(self, topicname, groupname, permissionname):
        if permissionname.lower() == 'read':
            permission = KafkaOperation.Read
        elif permissionname.lower() == 'write':
            permission = KafkaOperation.Write
        else:
            return f'Bad permission ({permissionname}) supplied', None
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
        if permissionname.lower() == 'read':
            permission = KafkaOperation.Read
        elif permissionname.lower() == 'write':
            permission = KafkaOperation.Write
        else:
            return 
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