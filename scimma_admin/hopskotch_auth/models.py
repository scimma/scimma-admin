from __future__ import annotations

from typing import Optional
from dataclasses import dataclass

import secrets
import string
from django.db import models, transaction
from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django_enumfield import enum
import hashlib
import uuid
import base64
from passlib.hash import scram
from passlib.utils import saslprep
import hmac
import re


class SCRAMAlgorithm(enum.Enum):
    SHA256 = 1
    SHA512 = 2

    def hash_function(self):
        """Return a hashlib hasher for the hash algorithm. """
        if self == SCRAMAlgorithm.SHA256:
            return hashlib.sha256
        if self == SCRAMAlgorithm.SHA512:
            return hashlib.sha512
        raise NotImplementedError("unimplemented hash")

    def iana_name(self):
        """Return the IANA text name of the hash, as per RFC8122.
        (http://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml)
        """
        if self == SCRAMAlgorithm.SHA256:
            return "sha-256"
        if self == SCRAMAlgorithm.SHA512:
            return "sha-512"
        NotImplementedError("unimplemented hash")


class SCRAMCredentials(models.Model):
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    username = models.CharField(
        max_length=256,
        unique=True,
    )  # Limit chosen pretty arbitrarily.

    # The SCRAM hashing algorithm used, as defined in RFC5802.
    algorithm = enum.EnumField(
        SCRAMAlgorithm,
        editable=False,
    )
    # The SCRAM 'Salt' as defined in RFFC5802.
    salt = models.BinaryField(
        max_length=128,
        editable=False,
    )
    # The SCRAM 'ServerKey' as defined in RFC5802.
    server_key = models.BinaryField(
        max_length=256,
        editable=False,
    )
    # The SCRAM 'StoredKey' as defined in RFC5802.
    stored_key = models.BinaryField(
        max_length=256,
        editable=False,
    )
    # The text representation of credentials used by Kafka.
    string_encoding = models.TextField(
        editable=False,
    )
    # The number of hash iterations used as defined in RFC5802.
    iterations = models.IntegerField(
        editable=False,
    )

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
	
    suspended = models.BooleanField(
        default = False,
    )

    @classmethod
    def generate(cls, owner: User, username: str, password: str, alg: SCRAMAlgorithm,
                 salt: Optional[bytes] = None, iterations: int = 4096):

        """ Generate SCRAM credentials, hashing the given password using the given algorithm.

        If salt is unset, a random one is used.

        If iterations is unset, 4096 (the Kafka default) is used.
        """
        # Set number of rounds:
        scram_hasher = scram.using(rounds=iterations)
        # Set salt:
        if salt is not None:
            scram_hasher = scram_hasher.using(salt=salt)
        # Set algorithm (sha-1 must always be in the algorithm list):
        scram_hasher = scram_hasher.using(f"sha-1,{alg.iana_name()}")
        # Run the hash, taking care to normalize the password
        scram_hash = scram_hasher.hash(saslprep(password))
        salt, _, hashed_pw = scram.extract_digest_info(scram_hash, alg.iana_name())

        hash_func = alg.hash_function()
        server_key = hmac.new(hashed_pw, b"Server Key", hash_func).digest()
        client_key = hmac.new(hashed_pw, b"Client Key", hash_func).digest()
        stored_key = hash_func(client_key).digest()

        val = cls(
            owner=owner,
            username=username,
            algorithm=alg,
            salt=salt,
            server_key=server_key,
            stored_key=stored_key,
            iterations=iterations,
            string_encoding=cls.string_encode(salt, stored_key, server_key, iterations),
        )
        return val

    @staticmethod
    def string_encode(salt, stored_key, server_key, iterations) -> bytes:
        """Emits the SCRAMCredentials as a Kafka-style base64-encoded sequence of ASCII
        keyval pairs.

        """
        parts = [
            b"salt=" + base64.b64encode(salt),
            b"stored_key=" + base64.b64encode(stored_key),
            b"server_key=" + base64.b64encode(server_key),
            b"iterations=" + str(iterations).encode("ascii")
        ]
        return b",".join(parts)

    @classmethod
    def from_string(cls, raw: str) -> SCRAMCredentials:
        """Read the base64-encoded Kafka-style format.

        The user, algorithm, and ID fields are left unset.
        """
        parts = raw.split(",")
        keyval = dict(p.split("=", 1) for p in parts)
        return SCRAMCredentials(
            salt=base64.b64decode(keyval['salt']),
            stored_key=base64.b64decode(keyval['stored_key']),
            server_key=base64.b64decode(keyval['server_key']),
            iterations=int(keyval['iterations']),
            string_encoding=raw,
        )

    @staticmethod
    def b64string(val: bytes) -> str:
        return base64.b64encode(val).decode("ascii")


def delete_credentials(user, cred_username):
    creds = SCRAMCredentials.objects.get(
        username=cred_username,
        owner_id=user.id,
    )
    creds.delete()


def new_credentials(owner):
    username = rand_username(owner)

    alphabet = string.ascii_letters + string.digits
    rand_password = "".join(secrets.choice(alphabet) for i in range(32))
    rand_salt = secrets.token_bytes(32)
    creds = SCRAMCredentials.generate(
        owner=owner,
        username=username,
        password=rand_password,
        alg=SCRAMAlgorithm.SHA512,
        salt=rand_salt,
    )
    creds.save()
    bundle = CredentialGenerationBundle(
        creds=creds,
        username=username,
        password=rand_password,
    )
    return bundle


@dataclass
class CredentialGenerationBundle:
    """ The collection of data generated ephemerally for new user credentials. """
    creds: SCRAMCredentials
    username: str
    password: str


def rand_username(owner: User) -> str:
    """ Return a random username. It's the user's domain-less email address,
    suffixed with 8 random hex characters.

    For example, 'swnelson@uw.edu' might get 'swnelson-03ea65d4'.
    """
    owner_emailname = owner.email.split("@")[0]
    rand_username_suffix = secrets.token_hex(nbytes=4)
    return f"{owner_emailname}-{rand_username_suffix}"


class MembershipStatus(enum.Enum):
    Member = 1
    Owner = 2


class Group(models.Model):
    name = models.CharField(
        max_length=256,
        unique=True,
    )
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL, 
        through='GroupMembership'
    )


class GroupMembership(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    group = models.ForeignKey(
        Group,
        on_delete=models.CASCADE,
    )
    status = enum.EnumField(
        MembershipStatus,
        editable=True,
    )


def is_group_member(user_id, group_id) -> bool:
    return GroupMembership.objects.filter(
        models.Q(status=MembershipStatus.Member) | models.Q(status=MembershipStatus.Owner),
        user_id=user_id,
        group_id=group_id,
    ).exists()


def is_group_owner(user_id, group_id) -> bool:
    return GroupMembership.objects.filter(
        models.Q(status=MembershipStatus.Owner),
        user_id=user_id,
        group_id=group_id,
    ).exists()


class KafkaTopic(models.Model):
    owning_group = models.ForeignKey(
        Group,
        on_delete=models.CASCADE,
    )
    name = models.CharField(
        max_length=249, # see https://github.com/apache/kafka/commit/ad3dfc6ab25c3f80d2425e24e72ae732b850dc60
        editable=False,
    )
    publicly_readable = models.BooleanField(
        default = False,
    )


def validate_topic_name(name: str) -> bool:
    # https://github.com/apache/kafka/blob/bc55f85237cb46e73c6774298cf308060a4a739c/clients/src/main/java/org/apache/kafka/common/internals/Topic.java#L30
    valid = re.compile("^[a-zA-Z0-9._-]{1,249}$")
    return re.match(valid, name)


class KafkaOperation(enum.Enum):
    All = 1
    Read = 2
    Write = 3
    Create = 4
    Delete = 5
    Alter = 6
    Describe = 7
    ClusterAction = 8
    DescribeConfigs = 9
    AlterConfigs = 10
    IdempotentWrite = 11


class GroupKafkaPermission(models.Model):
    principal = models.ForeignKey(
        Group,
        on_delete=models.CASCADE,
    )
    topic = models.ForeignKey(
        KafkaTopic,
        on_delete=models.CASCADE,
    )
    operation = enum.EnumField(
        KafkaOperation,
        editable=False,
    )

    def __eq__(self, other: GroupKafkaPermission) -> bool:
        return self.principal==other.principal \
           and self.topic==other.topic \
           and self.operation==other.operation

    def __hash__(self):
        return hash((self.principal, self.topic, self.operation))


def add_kafka_permission_for_group(group_id: str, topic: KafkaTopic, operation: KafkaOperation):
    group = Group.objects.get(id=group_id)
    new_record = GroupKafkaPermission(principal=group, topic=topic, operation=operation)
    
    # look up all permissions for this group/topic combination to figure out if the new record is 
    # redundant or some old ones need to be replaced
    existing = GroupKafkaPermission.objects.filter(principal=group_id, topic=topic.id)
    
    if existing.exists():
        if new_record in existing:
            # the exact permission we're trying to create already exists, 
            # so we can do nothing and declare success
            return
        if len(existing)==1 and existing[0].operation==KafkaOperation.All:
            # the existing permission is broader than the one being added,  
            # so we do not need to actually add it
            return
    
    # we do need to create a record
    with transaction.atomic():
        new_record.save()
        # If we wrote an "All" permission, then clean up any other permissions since 
        # they're redundant.
        if existing.exists() and operation==KafkaOperation.All:
            existing.delete()


def remove_kafka_permission_for_group(permission: GroupKafkaPermission, owning_group_id: str=None) -> bool:
    if owning_group_id is None:
        topic = permission.topic
        owning_group_id = topic.owning_group
    if permission.principal == owning_group_id: # refuse to take away access from the owning group
        return False
    with transaction.atomic():
        permission.delete()
        # clean up any uses by users in the group of this permission
        for membership in GroupMembership.objects.filter(group_id=permission.principal):
            user_creds = SCRAMCredentials.objects.filter(owner=membership.user)
            user_memberships = GroupMembership.objects.filter(user=membership.user)
            user_group_perms = {}
            for cred in user_creds:
                permissions_to_check = CredentialKafkaPermission.objects.filter(principal=cred).select_related('parent')
                # for each credential we must see if it has a permission which
                # derives from the permission being removed
                for cred_perm in permissions_to_check:
                    if cred_perm.parent!=permission:
                        continue # great, this one is not affected by this change
                    # if affected, we need to check whether there is any other valid derivation for this 
                    # permission which could replace the one being removed
                    repair_or_delete_permission(cred_perm, 
                                                lambda other_group_perm: other_group_perm==permission,
                                                user_memberships, user_group_perms)

    return True
    

class CredentialKafkaPermission(models.Model):
    principal = models.ForeignKey(
        SCRAMCredentials,
        on_delete=models.CASCADE,
    )
    # individual credentials derive their permissions from group permissions,
    # so we track that relationship in order to coordinate changes
    parent = models.ForeignKey(
        GroupKafkaPermission,
        on_delete=models.CASCADE
    )
    topic = models.ForeignKey(
        KafkaTopic,
        on_delete=models.CASCADE,
    )
    operation = enum.EnumField(
        KafkaOperation,
        editable=False,
    )


# This needs to be a character which is valid neither in Kafka topic names nor in enum names
cred_perm_encoding_separator=':'


def encode_cred_permission(parent_id, topic_id, operation) -> str:
    return cred_perm_encoding_separator.join(map(str, [parent_id, topic_id, operation]))


# returns tuples of (parent ID, topic ID, operation type)
def decode_cred_permission(encoded: str):
    parts = encoded.split(cred_perm_encoding_separator, 3)
    if len(parts) != 3:
        raise ValueError("Invalid encoded credential permission")
    try:
        op = KafkaOperation[parts[2]]
    except KeyError:
        raise ValueError("Invalid encoded credential permission")
    return (parts[0], parts[1], op)


# determine whether credential permission can be validly derived from the given group permission
def supporting_permission(group_perm: GroupKafkaPermission, cred_perm: CredentialKafkaPermission) -> bool:
    if cred_perm.topic != group_perm.topic:
        return False
    return group_perm.operation == KafkaOperation.All \
      or cred_perm.operation == group_perm.operation


# returns tuples of (parent ID, topic ID, topic name, perm type)
def all_permissions_for_user(user):
    possible_permissions = []
    for membership in user.groupmembership_set.all():
        group = membership.group
        group_permissions = GroupKafkaPermission.objects.filter(principal=group).select_related('topic')
        for permission in group_permissions:
            if permission.operation==KafkaOperation.All:
                for subpermission in KafkaOperation.__members__.items():
                    possible_permissions.append((permission.id,permission.topic.id,permission.topic.name,subpermission[1]))
            else:
                possible_permissions.append((permission.id,permission.topic.id,permission.topic.name,permission.operation))
    # sort and eliminate duplicates
    # sort on operation
    possible_permissions.sort(key=lambda p: p[3])
    # sort on topic names, because that looks nice for users, but since there is a bijection 
    # between topic names and IDs this will place all matching topic IDs together in blocks 
    # in some order
    possible_permissions.sort(key=lambda p: p[2])
    
    def equivalent(p1, p2):
        return p1[1] == p2[1] and p1[3]==p2[3];

    # remove adjacent (practical) duplicates which have different permission IDs
    dedup = []
    last = None
    for p in possible_permissions:
        if last is None or not equivalent(last,p):
            dedup.append(p)
            last=p
    
    return dedup


# Find a new, non-excluded group permission which can support the given 
# credential permission (permission), or delete it if none can be found.  
# exclude is a callable which will be called with each relevant group permission 
# whose return value should indicate whether it is to be ignored or not.
# user_memberships should be the set of group memberships for the user who owns
# permission
# group_permissions is a cache of the permissions belonging to groups of which
# the user is a member. It will be automatically updated. 
def repair_or_delete_permission(permission, exclude, user_memberships, group_permissions):
    for membership in user_memberships:
        # fetch permissions for this group if not already cached
        if not membership.group_id in group_permissions:
            group_permissions[membership.group_id] = GroupKafkaPermission.objects.filter(principal=membership.group_id)
        for group_perm in group_permissions[membership.group_id]:
            if exclude(group_perm):
                continue # this is one of the permissions we cannot use
            if supporting_permission(group_perm, permission):
                # this other group permission is a valid substitute for the one which is 
                #going away, so we can correct the credential permission instead of removing it
                permission.parent = group_perm
                permission.save()
                return True
    # if we could not find a way to fix the permission we must delete it
    permission.delete()
    return False


# remove all permissions the given user recieved via the given group, either 
# because the user is being removed from that group or the group is being
# deleted entirely, retaining credential permissions if they can be equivalently 
# constructed via another group permission
def remove_user_group_permissions(user_id, group_id):
    # must check all credentials owned by this user
    user_creds = SCRAMCredentials.objects.filter(owner=user_id)
    # we will potentially need to know all other groups to which this user belongs
    user_memberships = GroupMembership.objects.filter(user=user_id).exclude(group=group_id)
    group_permissions = {} # a cache for permissions of groups to which the user belongs
    for cred in user_creds:
        permissions_to_check = CredentialKafkaPermission.objects.filter(principal=cred).select_related('parent')
        # for each credential we must see if it has a permission which derives from
        # a group permission affected by this change
        for permission in permissions_to_check:
            if permission.parent.principal.id!=int(group_id):
                continue # great, this one is not affected by this change 
            # if affected, we need to check whether there is any other valid derivation for this 
            # permission which could replace the one being removed
            repair_or_delete_permission(permission, 
                                        lambda group_perm: group_perm.principal==group_id,
                                        user_memberships, group_permissions)


# delete all permissions which refer to a given topic
def delete_topic_permissions(topic_id):
    CredentialKafkaPermission.objects.filter(topic=topic_id).delete()
    GroupKafkaPermission.objects.filter(topic=topic_id).delete()
