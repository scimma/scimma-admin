from typing import Dict, List, Set

from .models import *
from .result import Result, Ok, Err

class DirectInterface:
    def __init__(self) -> None:
        pass

    def new_credential(self, owner: User, description: str) -> Result[Dict[str, str], str]:
        """
        Generate a new Kafka (SCRAM) cedential for a user.

        Args:
            owner: The requesting user, who will be the owner of the new credential
            description: Any descriptive text the user wants to attach to the credential

            Return: A dictionary describing the new credential. This will contian two keys:
                    'username', the name of the credential (*not* the owning user), and 'password', the
                    plaintext password for the credential. The plaintext password cannot be retrieved by
                    any other means and is not stored so callers must be careful not to lose it.
        """
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

        return Ok(data)

    def delete_credential(self, username: str, cred_name: str) -> Result[None, str]:
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return Err(f'User "{username}" does not exist')
        try:
            credential = SCRAMCredentials.objects.get(username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Credential "{cred_name}" does not exist')
        if credential.owner.username != username and not user.is_staff:
            return Err(f'Credential can only be deleted by the owning user or a staff member')
        credential.delete()
        return Ok(None)

    def update_credential(self, user: User, cred_name: str, description: str) -> Result[None, str]:
        try:
            credential = SCRAMCredentials.objects.get(owner=user, username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Credentials "{cred_name}" does not exist')
        credential.description = description
        credential.save()
        return Ok(None)

    def get_credential(self, requesting_user: User, cred_name: str) -> Result[SCRAMCredentials, str]:
        # TODO: check that requesting_user has authority to manipulate owning_user's credentials
        try:
            credential = SCRAMCredentials.objects.get(username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err('Could not find user or credential')
        return Ok(credential)

    def get_user_credentials(self, user: User) -> Result[List[SCRAMCredentials], str]:
        """
        Get all credentials belonging to a user

        Args:
            user: The the owning user, who must also be the user making the request

        Return: A list of credentials
        """
        credentials = list(user.scramcredentials_set.all())
        return Ok(credentials)

    def get_credential_permissions(self, user: User, cred_name: str) -> Result[List[CredentialKafkaPermission], str]:
        try:
            cred = SCRAMCredentials.objects.get(owner=user, username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(f'User or credential not found')
        perms = list(CredentialKafkaPermission.objects.filter(principal=cred))
        return Ok(perms)

    def add_credential_permission(self, user: User, cred_name: str, topic_name: str, permission: KafkaOperation) -> Result[None, str]:
        try:
            cred = SCRAMCredentials.objects.get(username=cred_name)
            if cred.owner.username != user.username and not user.is_staff:
                return Err(f'User "{user.username}" does not have permissions for credential {cred_name} and is not staff')
        except:
            return Err(f'Credential with owner "{user.username}" and credential name "{cred_name}"')
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Topic with name "{topic_name}"" does not exist')

        existing_perm = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic, operation=KafkaOperation.All)
        if existing_perm.exists():
            # All permission already exists; any addition would be redundant
            return Ok(None)
        existing_perm = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic, operation=permission)
        if existing_perm.exists():
            # Exact permission already exists; nothing to do
            return Ok(None)

        notional_perm = CredentialKafkaPermission(principal=cred, topic=topic, operation=permission)
        # Do not 'create' notional_perm into the database yet as we have not set its parent permission,
        # and may or may not find a suitable value for that

        # Try to discover some group permission which can serve as a basis for this credential permission
        group_perms = GroupKafkaPermission.objects.filter(models.Q(operation=KafkaOperation.All) |
                                                          models.Q(operation=permission),
                                                          topic=topic
                                                          )

        base_perm: Optional[GroupKafkaPermission] = None
        for group_perm in group_perms:
            if is_group_member(user.id, group_perm.principal.id):
                base_perm = group_perm
                break

        if base_perm is None:
            return Err(f"User {user.username} does not have permission via any group to use "
                       f"{permission} access to topic {topic_name}")

        notional_perm.parent = base_perm
        notional_perm.create()
        return Ok(None)

    def remove_credential_permission(self, user: User, cred_name: str, topic_name: str, permission: KafkaOperation) -> Result[None, str]:
        try:
            cred = SCRAMCredentials.objects.get(owner=user, username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Credential {cred_name} does not exist')
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Topic {topic_name} does not exist')
        to_delete = CredentialKafkaPermission.objects.filter(
            principal=cred,
            topic=topic,
            operation=permission
        )
        to_delete.delete()
        return Ok(None)

    def suspend_credential(self, requesting_user: User, credential: SCRAMCredentials) -> Result[None, str]:
        # TODO: check that requesting_user has valid authority
        credential.suspended = True
        credential.save()
        return Ok(None)

    def unsuspend_credential(self, requesting_user: User, credential: SCRAMCredentials) -> Result[None, str]:
        # TODO: check that requesting_user has valid authority
        credential.suspended = False
        credential.save()
        return Ok(None)

    def toggle_credential_suspension(self, requesting_user: User, credential: SCRAMCredentials) -> Result[bool, str]:
        # TODO: check that requesting_user has valid authority
        credential.suspended = not credential.suspended
        credential.save()
        return Ok(credential.suspended)

    def create_group(self, user: User, group_name: str, description: str) -> Result[None, str]:
        if not user.is_staff:
            return Err(f'User "{user.username}" is not staff. Only staff is able to create groups')
        if not validate_group_name(group_name):
            return Err('Invalid group name')
        if Group.objects.filter(name=group_name).exists():
            return Err('Group already exists')
        group = Group.objects.create(name=group_name, description=description)
        group.save()

        return Ok(None)

    def delete_group(self, username: str, group_name: str) -> Result[None, str]:
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return Err(f'User "{username}" does not exist')
        if not user.is_staff:
            return Err(f'User "{username}" is not staff and cannot delete groups')
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Group "{group_name}" does not exist')
        # TODO: is this needed, or is it covered by cascading delete rules? Otherwise, is a transaction needed?
        for member in group.members.all():
            remove_user_group_permissions(member.id, group.id)
        group.delete()
        return Ok(None)

    def add_member_to_group(self, group_name: str, username: str, status: MembershipStatus) -> Result[None, str]:
        try:
            group = Group.objects.get(name=group_name)
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return Err('User or group does not exist')
        cur_membership = GroupMembership.objects.filter(user=user, group=group)
        if cur_membership.exists():
            return Err(f'User "{username}" is already a member of group "{group_name}"')
        cur_membership = GroupMembership.objects.create(user=user, group=group, status=status)
        return Ok(None)

    def remove_member_from_group(self, group_name: str, username: str) -> Result[None, str]:
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return Err(f'User "{username}" does not exist')
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Group "{group_name}" does not exist')
        membership = GroupMembership.objects.filter(user=user, group=group)
        if not membership.exists():
            return Err(f'Group "{group_name}" does not include member "{username}"')
        membership.delete()
        return Ok(None)

    def create_topic(self, user: User, group_name: str, topic_name: str, description: str, publicly_readable: bool) -> Result[None, str]:
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err('Group not found')
        if not validate_topic_name(topic_name):
            return Err("Invalid topic name")
        # TODO: Check that topic does not already exist
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
        return Ok(None)

    def delete_topic(self, username: str, topic_name: str) -> Result[None, str]:
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return Err(f'User "{username}" does not exist')
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Topic "{topic_name}" does not exist')
        if not GroupMembership.objects.filter(user=user, group=topic.owning_group, status=MembershipStatus.Owner).exists() or not user.is_staff:
            return Err('User cannot delete topic because they are not an owner or a staff member')
        with transaction.atomic():
            CredentialKafkaPermission.objects.filter(topic=topic).delete()
            GroupKafkaPermission.objects.filter(topic=topic).delete()
            topic.delete()
        return Ok(None)

    def get_topic(self, topic_name: str) -> Result[KafkaTopic, str]:
        try:
            return Ok(KafkaTopic.objects.get(name=topic_name))
        except ObjectDoesNotExist as dne:
            return Err(f'Topic "{topic_name}" does not exist')

    def update_topic_description(self, user: User, topic: KafkaTopic, description: str) -> Result[None, str]:
        #TODO: check that user has authority to do this
        topic.description = description
        topic.save()
        return Ok(None)

    def update_topic_visibility(self, user: User, topic: KafkaTopic, public: bool) -> Result[None, str]:
        #TODO: check that user has authority to do this
        topic.publicly_readable = public
        topic.save()
        return Ok(None)

    def add_group_topic_permission(self, user: User, group_name: str, topic_name: str, permission: KafkaOperation) -> Result[None, str]:
        #TODO: check that user has authority to do this
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Topic "{topic_name}" does not exist')
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Group "{group_name}" does not exist')
        add_kafka_permission_for_group(group, topic, permission)
        return Ok(None)


    def remove_group_topic_permission(self, user: User, group_name: str, topic_name: str, permission: KafkaOperation) -> Result[None, str]:
        #TODO: check that the user has authority to do this
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Topic "{topic_name}" does not exist')
        try:
            group = Group.objects.get(name=group_name)
        except:
            return Err(f'Group "{group_name}" does not exist')
        try:
            perm = GroupKafkaPermission.objects.get(principal=group, topic=topic, operation=permission)
        except ObjectDoesNotExist as dne:
            return Err(f'Permission "{permission}" for topic "{topic_name}" does not exist')
        remove_kafka_permission_for_group(perm, group.id)
        return Ok(None)

    def get_user_accessible_topics(self, user: User) -> Result[List[Tuple[KafkaTopic, str]], str]:
        data: List[Tuple[KafkaTopic, str]] = []
        memberships = GroupMembership.objects.filter(user=user)
        added_topics: Set[str] = set()
        for membership in memberships:
            group = membership.group
            group_permissions = GroupKafkaPermission.objects.filter(principal=group)
            for permission in group_permissions:
                if permission.topic.name not in added_topics:
                    data.append((permission.topic, group.name))
                    added_topics.add(permission.topic.name)
        public_topics = KafkaTopic.objects.filter(publicly_readable=True)
        for topic in public_topics:
            if topic.name not in added_topics:
                data.append((topic, "public"))
                added_topics.add(topic.name)
        return Ok(data)

    def get_user_group_memberships(self, user: User) -> Result[List[GroupMembership], str]:
        memberships = user.groupmembership_set.all().select_related('group')
        return Ok(list(memberships))

    def get_all_users(self) -> Result[List[User], str]:
        users = User.objects.all()
        return Ok(list(users))

    def get_all_credentials(self) -> Result[List[SCRAMCredentials], str]:
        credentials = SCRAMCredentials.objects.all()
        return Ok(list(credentials))

    def get_all_topics(self) -> Result[List[KafkaTopic], str]:
        topics = KafkaTopic.objects.all()
        return Ok(list(topics))

    def get_all_groups(self) -> Result[List[Group], str]:
        groups = Group.objects.all()
        return Ok(list(groups))

    def get_group(self, group_name: str) -> Result[Group, str]:
        try:
            return Ok(Group.objects.get(name=group_name))
        except ObjectDoesNotExist as dne:
            return Err(f'Group "{group_name}" does not exist')

    def get_group_members(self, group: Group) -> Result[List[GroupMembership], str]:
        data: List[GroupMembership] = []
        for member in group.members.all():
            user = User.objects.get(username=member.username)
            membership = GroupMembership.objects.get(group=group, user=user)
            data.append(membership)
        return Ok(data)

    def get_group_topics(self, group_name: str) -> Result[List[KafkaTopic], str]:
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Group "{group_name}" does not exist')
        topics = KafkaTopic.objects.filter(owning_group=group)
        return Ok(list(topics))

    def is_user_admin(self, username: str) -> Result[bool, str]:
        try:
            user = User.objects.get(username=username)
            return Ok(user.is_staff)
        except ObjectDoesNotExist as dne:
            return Err(f'User "{username}" does not exist')

    def get_groups_with_access_to_topic(self, topic: KafkaTopic) -> Result[List[GroupKafkaPermission], str]:
        """
        Fetches all group permissions attached to the specified topic

        Args:
            topic: The topic whose permissions to return

        Returns: A list of the topic's current permissions
        """
        permissions = GroupKafkaPermission.objects.filter(topic=topic)
        return Ok(list(permissions))

    def get_group_accessible_topics(self, group: Group) -> Result[List[GroupKafkaPermission], str]:
        """
        Fetches all topic permissions granted to the specified group

        Args:
            group: The group whose permissions should be looked up

        Returns: A list of the group's current permissions
        """
        permissions = GroupKafkaPermission.objects.filter(principal=group)
        return Ok(list(permissions))

    def change_user_group_status(self, username: str, group_name: str, status: MembershipStatus) -> Result[None, str]:
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return Err(f'User "{username}" does not exist')
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Group "{group_name}" does not exist')
        try:
            membership = GroupMembership.objects.get(user=user, group=group)
        except ObjectDoesNotExist as dne:
            return Err(f'User does not have a membership to the specified group')
        membership.status = status
        membership.save()
        return Ok(None)

    def get_group_permissions_for_topic(self, group_name: str, topic_name: str) -> Result[List[GroupKafkaPermission], str]:
        """
        Fetch all permissions the given group has for the given topic

        Args:
            group_name: The name of the group for which to look up permissions
            topic_name: The name olf the topic for which to look up permissions

        Returns: A list of all fo the group's current permissions for the topic
        """
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Group "{group_name}" does not exist')
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Topic "{topic_name}" does not exist')
        all_perms = GroupKafkaPermission.objects.filter(principal=group, topic=topic)
        return Ok(list(all_perms))

    def modify_group_description(self, group_name: str, description: str) -> Result[None, str]:
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Group "{group_name}" does not exist')
        group.description = description
        group.save()
        return Ok(None)

    def get_available_credential_permissions(self, user: User, topic: Optional[KafkaTopic]=None) -> Result[List[Tuple[GroupKafkaPermission, str]], str]:
        PermissionPair = Tuple[GroupKafkaPermission, str]
        possible_permissions: List[PermissionPair] = []
        for membership in user.groupmembership_set.all():
            group = membership.group
            if topic is None:
                group_permissions = GroupKafkaPermission.objects.filter(principal=group).select_related('topic')
            else:
                group_permissions = GroupKafkaPermission.objects.filter(principal=group, topic=topic).select_related('topic')
            for permission in group_permissions:
                if permission.operation==KafkaOperation.All:
                    for subpermission in KafkaOperation.__members__.items():
                        possible_permissions.append((permission, subpermission[1].name))
#                        possible_permissions.append({
#                            'group': permission.principal.name,
#                            'topic_id': permission.topic.id,
#                            'topic': permission.topic.name,
#                            'group_description': permission.principal.description,
#                            'topic_description': permission.topic.description,
#                            'operation': subpermission[1].name
#                        })
                        #possible_permissions.append((permission.topic.name,permission.topic.description, permission.principal.name, subpermission[1].name))
                else:
                    possible_permissions.append((permission, permission.operation.name))
#                    possible_permissions.append({
#                        'group': permission.principal.name,
#                        'topic_id': permission.topic.id,
#                        'topic': permission.topic.name,
#                        'group_description': permission.principal.description,
#                        'topic_description': permission.topic.description,
#                        'operation': permission.operation.name
#                    })
                    #possible_permissions.append((permission.topic.name,permission.operation.name))
        # sort and eliminate duplicates
        # sort on operation
        possible_permissions.sort(key=lambda p: p[1])
        #possible_permissions.sort(key=lambda p: p['operation'])
        # sort on topic names, because that looks nice for users, but since there is a bijection
        # between topic names and IDs this will place all matching topic IDs together in blocks
        # in some order
        #possible_permissions.sort(key=lambda p: p[0])
        #possible_permissions.sort(key=lambda p: p['topic'])
        possible_permissions.sort(key=lambda p: p[0].topic.name)

        def equivalent(p1: PermissionPair, p2: PermissionPair) -> bool:
            #return p1[0] == p2[0] and p1[-1] == p2[-1]
            #return p1['topic_id'] == p2['topic_id'] and p1['operation'] == p2['operation']
            return p1[0].topic == p2[0].topic and p1[1] == p2[1]

        # remove adjacent (practical) duplicates which have different permission IDs
        dedup: List[PermissionPair] = []
        last = None
        for p in possible_permissions:
            if last is None or not equivalent(last,p):
                dedup.append(p)
                last=p

        return Ok(dedup)

    def get_credential_permissions_for_topic(self, cred_name: str, topic_name: str) -> Result[List[CredentialKafkaPermission], str]:
        try:
            cred = SCRAMCredentials.objects.get(username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Credential "{cred_name}" does not exist')
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(f'Topic "{topic_name}" does not exist')
        cred_perms = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic)
        return Ok(list(cred_perms))
