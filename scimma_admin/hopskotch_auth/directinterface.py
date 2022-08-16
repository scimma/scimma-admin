from dataclasses import dataclass
from typing import Dict, List, Set

from .models import *
from .result import Result, Ok, Err

@dataclass
class Error:
    desc: str
    status: int

class DirectInterface:
    def __init__(self) -> None:
        pass

    def new_credential(self, owner: User, description: str) -> Result[Dict[str, str], Error]:
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

    def delete_credential(self, user: User, cred_name: str) -> Result[None, Error]:
        """
        Delete a SCRAM (Kafka) credential

        Args:
            user: The user requesting the deletion. Must be either the credential owner or a staff member
            cred_name: The name of the credential to delete
        """
        try:
            credential = SCRAMCredentials.objects.get(username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Credential "{cred_name}" does not exist', 404))
        if credential.owner != user and not user.is_staff:
            return Err(Error(f'Credentials can only be deleted by the owning user or a staff member', 403))
        credential.delete()
        return Ok(None)

    def update_credential(self, user: User, cred_name: str, description: str) -> Result[None, Error]:
        try:
            credential = SCRAMCredentials.objects.get(owner=user, username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Credential "{cred_name}" does not exist', 404))
        if credential.owner != user and not user.is_staff:
            return Err(Error(f'Credentials can only be modified by the owning user or a staff member', 403))
        credential.description = description
        credential.save()
        return Ok(None)

    def get_credential(self, requesting_user: User, cred_name: str) -> Result[SCRAMCredentials, Error]:
        # TODO: check that requesting_user has authority to manipulate owning_user's credentials
        try:
            credential = SCRAMCredentials.objects.get(username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Credential "{cred_name}" does not exist', 404))
        if credential.owner != requesting_user and not requesting_user.is_staff:
            return Err(Error(f'Credentials can only be inspected by the owning user or a staff member', 403))
        return Ok(credential)

    def get_user_credentials(self, requesting_user: User, target_user: User) -> Result[List[SCRAMCredentials], Error]:
        """
        Get all credentials belonging to a user

        Args:
            user: The the owning user, who must also be the user making the request

        Return: A list of credentials
        """
        if requesting_user != target_user and not requesting_user.is_staff:
            return Err(Error(f'Credentials can only be inspected by the owning user or a staff member', 403))
        credentials = list(target_user.scramcredentials_set.all())
        return Ok(credentials)

    def get_credential_permissions(self, requesting_user: User, owner: User, cred_name: str) -> Result[List[CredentialKafkaPermission], Error]:
        if requesting_user != owner and not requesting_user.is_staff:
            return Err(Error(f'Credentials can only be inspected by the owning user or a staff member', 403))
        try:
            cred = SCRAMCredentials.objects.get(owner=owner, username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Credential {cred_name} not found',404))
        perms = list(CredentialKafkaPermission.objects.filter(principal=cred))
        return Ok(perms)

    def add_credential_permission(self, requesting_user: User, cred_name: str, topic_name: str, permission: KafkaOperation) -> Result[None, Error]:
        try:
            cred = SCRAMCredentials.objects.get(username=cred_name)
            if cred.owner != requesting_user and not requesting_user.is_staff:
                return Err(Error(f'User "{requesting_user.username}" does not have permissions for '
                                 f'credential {cred_name} and is not staff', 403))
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Credential with name "{cred_name}" not found', 404))
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Topic with name "{topic_name}"" does not exist', 404))

        existing_perm = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic, operation=KafkaOperation.All)
        if existing_perm.exists():
            # All permission already exists; any addition would be redundant
            return Ok(None)
        existing_perm = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic, operation=permission)
        if existing_perm.exists():
            # Exact permission already exists; nothing to do
            return Ok(None)

        #notional_perm = CredentialKafkaPermission(principal=cred, topic=topic, operation=permission)
        # Do not 'create' notional_perm into the database yet as we have not set its parent permission,
        # and may or may not find a suitable value for that

        # Try to discover some group permission which can serve as a basis for this credential permission
        group_perms = GroupKafkaPermission.objects.filter(models.Q(operation=KafkaOperation.All) |
                                                          models.Q(operation=permission),
                                                          topic=topic
                                                          )

        base_perm: Optional[GroupKafkaPermission] = None
        for group_perm in group_perms:
            if is_group_member(requesting_user.id, group_perm.principal.id):
                base_perm = group_perm
                break

        if base_perm is None:
            return Err(Error(f"User {requesting_user.username} does not have permission via any group to "
                             f"use {permission} access to topic {topic_name}", 403))

        #notional_perm.parent = base_perm
        #notional_perm.create()
        CredentialKafkaPermission.objects.create(
            principal=cred,
            topic=topic,
            operation=permission,
            parent=base_perm
        )
        return Ok(None)

    def remove_credential_permission(self, user: User, cred_name: str, topic_name: str, permission: KafkaOperation) -> Result[None, Error]:
        try:
            cred = SCRAMCredentials.objects.get(owner=user, username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Credential {cred_name} does not exist', 404))
        if cred.owner != user and not user.is_staff:
            return Err(Error(f'Credentials can only be modified by the owning user or a staff member', 403))
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Topic {topic_name} does not exist', 404))
        to_delete = CredentialKafkaPermission.objects.filter(
            principal=cred,
            topic=topic,
            operation=permission
        )
        to_delete.delete()
        return Ok(None)

    def suspend_credential(self, requesting_user: User, credential: SCRAMCredentials) -> Result[None, Error]:
        if not requesting_user.is_staff:
            return Err(Error(f'Credentials can only be suspended staff members', 403))
        credential.suspended = True
        credential.save()
        return Ok(None)

    def unsuspend_credential(self, requesting_user: User, credential: SCRAMCredentials) -> Result[None, Error]:
        if not requesting_user.is_staff:
            return Err(Error(f'Credentials can only be unsuspended staff members', 403))
        credential.suspended = False
        credential.save()
        return Ok(None)

    def toggle_credential_suspension(self, requesting_user: User, credential: SCRAMCredentials) -> Result[bool, Error]:
        if not requesting_user.is_staff:
            return Err(Error(f'Credentials can only be suspended staff members', 403))
        credential.suspended = not credential.suspended
        credential.save()
        return Ok(credential.suspended)

    def create_group(self, user: User, group_name: str, description: str) -> Result[None, Error]:
        if not user.is_staff:
            return Err(Error(f'User "{user.username}" is not staff. Only staff is able to create groups', 403))
        if not validate_group_name(group_name):
            return Err(Error('Invalid group name', 400))
        if Group.objects.filter(name=group_name).exists():
            return Err(Error('Group already exists', 400))
        group = Group.objects.create(name=group_name, description=description)
        group.save()

        return Ok(None)

    def delete_group(self, user: User, group_name: str) -> Result[None, Error]:
        if not user.is_staff:
            return Err(Error(f'User "{user.username}" is not staff and cannot delete groups', 403))
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Group "{group_name}" does not exist', 404))
        # TODO: is this needed, or is it covered by cascading delete rules? Otherwise, is a transaction needed?
        for member in group.members.all():
            remove_user_group_permissions(member.id, group.id)
        group.delete()
        return Ok(None)

    def add_member_to_group(self, requesting_user: User, group_name: str, username: str, status: MembershipStatus) -> Result[None, Error]:
        try:
            group = Group.objects.get(name=group_name)
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return Err(Error('User or group does not exist', 404))
        if not is_group_owner(requesting_user.id, group.id) and not requesting_user.is_staff:
            return Err(Error(f'User "{requesting_user.username}" is not staff or '
                             f'an owner of the {group.name} group', 403))
        cur_membership = GroupMembership.objects.filter(user=user, group=group)
        if cur_membership.exists():
            return Err(Error(f'User "{username}" is already a member of group "{group_name}"', 400))
        cur_membership = GroupMembership.objects.create(user=user, group=group, status=status)
        return Ok(None)

    def remove_member_from_group(self, requesting_user: User, group_name: str, username: str) -> Result[None, Error]:
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'User "{username}" does not exist', 404))
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Group "{group_name}" does not exist', 404))
        if not is_group_owner(requesting_user.id, group.id) and not requesting_user.is_staff:
            return Err(Error(f'User "{requesting_user.username}" is not staff or '
                             f'an owner of the {group.name} group', 403))
        membership = GroupMembership.objects.filter(user=user, group=group)
        if not membership.exists():
            return Err(Error(f'Group "{group_name}" does not include member "{username}"', 400))
        membership.delete()
        return Ok(None)

    def create_topic(self, user: User, group_name: str, topic_name: str, description: str, publicly_readable: bool) -> Result[None, Error]:
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(Error('Group not found', 404))
        if not is_group_owner(user.id, group.id) and not user.is_staff:
            return Err(Error(f'User "{user.username}" is not staff or '
                             f'an owner of the {group.name} group', 403))
        topic_name = group_name + '.' + topic_name
        if not validate_topic_name(topic_name):
            return Err(Error("Invalid topic name", 400))
        try:
            KafkaTopic.objects.get(name=topic_name)
            return Err(Error(f"Topic {topic_name} already exists", 400))
        except ObjectDoesNotExist as dne:
            pass  # creation can proceed
        topic = KafkaTopic.objects.create(
            owning_group = group,
            name = topic_name,
            publicly_readable = publicly_readable,
            description = description
        )
        _ = GroupKafkaPermission.objects.create(
            principal=group,
            topic=topic,
            operation=KafkaOperation.Read
        )
        _ = GroupKafkaPermission.objects.create(
            principal=group,
            topic=topic,
            operation=KafkaOperation.Write
        )
        return Ok(None)

    def delete_topic(self, user: User, topic_name: str) -> Result[None, Error]:
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Topic "{topic_name}" does not exist', 404))
        if not is_group_owner(user.id, topic.owning_group.id) and not user.is_staff:
            return Err(Error('User cannot delete topic because they are not a group owner or a staff member', 403))
        with transaction.atomic():
            CredentialKafkaPermission.objects.filter(topic=topic).delete()
            GroupKafkaPermission.objects.filter(topic=topic).delete()
            topic.delete()
        return Ok(None)

    def get_topic(self, topic_name: str) -> Result[KafkaTopic, Error]:
        # TODO: are there any limitations on which users may query topics, i.e. learn topic names and descriptions?
        try:
            return Ok(KafkaTopic.objects.get(name=topic_name))
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Topic "{topic_name}" does not exist', 404))

    def update_topic_description(self, user: User, topic: KafkaTopic, description: str) -> Result[None, Error]:
        if not is_group_owner(user.id, topic.owning_group.id) and not user.is_staff:
            return Err(Error('Only owning group owners and staff members can change topic descriptions', 403))
        topic.description = description
        topic.save()
        return Ok(None)

    def update_topic_public_readability(self, user: User, topic: KafkaTopic, public: bool) -> Result[None, Error]:
        if not is_group_owner(user.id, topic.owning_group.id) and not user.is_staff:
            return Err(Error('Only owning group owners and staff members can change topic public readability', 403))
        topic.publicly_readable = public
        topic.save()
        return Ok(None)

    def add_group_topic_permission(self, user: User, group_name: str, topic_name: str, permission: KafkaOperation) -> Result[None, Error]:
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Topic "{topic_name}" does not exist', 404))
        if not is_group_owner(user.id, topic.owning_group.id) and not user.is_staff:
            return Err(Error('Only owning group owners and staff members can grant access to a topic', 403))
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Group "{group_name}" does not exist', 404))
        add_kafka_permission_for_group(group, topic, permission)
        return Ok(None)


    def remove_group_topic_permission(self, user: User, group_name: str, topic_name: str, permission: KafkaOperation) -> Result[None, Error]:
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Topic "{topic_name}" does not exist', 404))
        if not is_group_owner(user.id, topic.owning_group.id) and not user.is_staff:
            return Err(Error('Only owning group owners and staff members can revoke access to a topic', 403))
        try:
            group = Group.objects.get(name=group_name)
        except:
            return Err(Error(f'Group "{group_name}" does not exist', 404))
        if(remove_kafka_permission_for_group(group, topic, permission)):
            return Ok(None)
        return Err(Error(f'Permission cannot be removed', 400))

    def get_user_accessible_topics(self, requesting_user: User, target_user: User) -> Result[List[Tuple[KafkaTopic, str]], Error]:
        if requesting_user != target_user and not requesting_user.is_staff:
            return Err(Error('Information about users may be fetched only by themselves and staff members', 403))
        data: List[Tuple[KafkaTopic, str]] = []
        memberships = GroupMembership.objects.filter(user=target_user)
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

    def get_user_group_memberships(self, requesting_user: User, target_user: User) -> Result[List[GroupMembership], Error]:
        if requesting_user != target_user and not requesting_user.is_staff:
            return Err(Error('Information about users may be fetched only by themselves and staff members', 403))
        memberships = target_user.groupmembership_set.all().select_related('group')
        return Ok(list(memberships))

    def get_all_users(self) -> Result[List[User], Error]:
        # Any user may fetch the full list of users
        users = User.objects.all()
        return Ok(list(users))

    def get_all_credentials(self, requesting_user: User) -> Result[List[SCRAMCredentials], Error]:
        if not requesting_user.is_staff:
            return Err(Error('Only staff members may list all credentials', 403))
        credentials = SCRAMCredentials.objects.all()
        return Ok(list(credentials))

    def get_all_topics(self, requesting_user: User) -> Result[List[KafkaTopic], Error]:
        if not requesting_user.is_staff:
            return Err(Error('Only staff members may list all credentials', 403))
        topics = KafkaTopic.objects.all()
        return Ok(list(topics))

    def get_all_groups(self) -> Result[List[Group], Error]:
        # Any user may fetch the full list of groups
        groups = Group.objects.all()
        return Ok(list(groups))

    def get_group(self, group_name: str) -> Result[Group, Error]:
        # Any user may query any group
        try:
            return Ok(Group.objects.get(name=group_name))
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Group "{group_name}" does not exist', 404))

    def get_group_members(self, requesting_user: User, group: Group) -> Result[List[GroupMembership], Error]:
        if not is_group_owner(requesting_user.id, group.id) and not requesting_user.is_staff:
            return Err(Error('Only group owners and staff members can list group members', 403))
        data: List[GroupMembership] = []
        for member in group.members.all():
            user = User.objects.get(username=member.username)
            membership = GroupMembership.objects.get(group=group, user=user)
            data.append(membership)
        return Ok(data)

    def get_group_topics(self, requesting_user: User, group_name: str) -> Result[List[KafkaTopic], Error]:
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Group "{group_name}" does not exist', 404))
        if not is_group_member(requesting_user.id, group.id) and not requesting_user.is_staff:
            return Err(Error('Only group members and staff members can list group topics', 403))
        topics = KafkaTopic.objects.filter(owning_group=group)
        return Ok(list(topics))

    """
    def is_user_admin(self, username: str) -> Result[bool, Error]:
        try:
            user = User.objects.get(username=username)
            return Ok(user.is_staff)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'User "{username}" does not exist', 404))
    """

    def get_groups_with_access_to_topic(self, requesting_user: User, topic: KafkaTopic) -> Result[List[GroupKafkaPermission], Error]:
        """
        Fetches all group permissions attached to the specified topic

        Args:
            topic: The topic whose permissions to return

        Returns: A list of the topic's current permissions
        """
        if not is_group_owner(requesting_user.id, topic.owning_group.id) and not requesting_user.is_staff:
            return Err(Error('Only owning group owners and staff members can list groups with access to a topic', 403))
        permissions = GroupKafkaPermission.objects.filter(topic=topic)
        return Ok(list(permissions))

    def get_group_accessible_topics(self, requesting_user: User, group: Group) -> Result[List[GroupKafkaPermission], Error]:
        """
        Fetches all topic permissions granted to the specified group

        Args:
            requesting_user: The user requesting the information
            group: The group whose permissions should be looked up

        Returns: A list of the group's current permissions
        """
        if not is_group_member(requesting_user.id, group.id) and not requesting_user.is_staff:
            return Err(Error('Only group members and staff members can list topics accessible to a group', 403))
        permissions = GroupKafkaPermission.objects.filter(principal=group)
        return Ok(list(permissions))

    def change_user_group_status(self, requesting_user: User, username: str, group_name: str, status: MembershipStatus) -> Result[None, Error]:
        try:
            user = User.objects.get(username=username)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'User "{username}" does not exist', 404))
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Group "{group_name}" does not exist', 404))
        if not is_group_owner(requesting_user.id, group.id) and not requesting_user.is_staff:
            return Err(Error("Only group owners and staff members can change group members' status", 403))
        try:
            membership = GroupMembership.objects.get(user=user, group=group)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'User does not have a membership to the specified group', 404))
        membership.status = status
        membership.save()
        return Ok(None)

    def get_group_permissions_for_topic(self, requesting_user: User, group_name: str, topic_name: str) -> Result[List[GroupKafkaPermission], Error]:
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
            return Err(Error(f'Group "{group_name}" does not exist', 404))
        if not is_group_member(requesting_user.id, group.id) and not requesting_user.is_staff:
            return Err(Error("Only group members and staff members can list a group's permissions for a topic", 403))
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Topic "{topic_name}" does not exist', 404))
        all_perms = GroupKafkaPermission.objects.filter(principal=group, topic=topic)
        return Ok(list(all_perms))

    def modify_group_description(self, requesting_user: User, group_name: str, description: str) -> Result[None, Error]:
        try:
            group = Group.objects.get(name=group_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Group "{group_name}" does not exist', 404))
        if not is_group_owner(requesting_user.id, group.id) and not requesting_user.is_staff:
            return Err(Error("Only group owner and staff members can set a group's description", 403))
        group.description = description
        group.save()
        return Ok(None)

    def get_available_credential_permissions(self, requesting_user: User, target_user: User, topic: Optional[KafkaTopic]=None) -> Result[List[Tuple[GroupKafkaPermission, str]], Error]:
        if requesting_user != target_user and not requesting_user.is_staff:
            return Err(Error(f"Information on permissions available to user's credential is available on to that user and staff members", 403))
    
        PermissionPair = Tuple[GroupKafkaPermission, str]
        possible_permissions: List[PermissionPair] = []
        for membership in target_user.groupmembership_set.all():
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

    def get_credential_permissions_for_topic(self, requesting_user: User, cred_name: str, topic_name: str) -> Result[List[CredentialKafkaPermission], Error]:
        try:
            cred = SCRAMCredentials.objects.get(username=cred_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Credential "{cred_name}" does not exist', 404))
        if requesting_user != cred.owner and not requesting_user.is_staff:
            return Err(Error(f"Information on permissions available to user's credential is available on to that user and staff members", 403))
        try:
            topic = KafkaTopic.objects.get(name=topic_name)
        except ObjectDoesNotExist as dne:
            return Err(Error(f'Topic "{topic_name}" does not exist', 404))
        cred_perms = CredentialKafkaPermission.objects.filter(principal=cred, topic=topic)
        return Ok(list(cred_perms))
