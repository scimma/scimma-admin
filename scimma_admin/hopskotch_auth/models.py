from __future__ import annotations

from typing import Optional
from dataclasses import dataclass

import secrets
import string
from django.db import models
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


def is_group_member(user, group):
    try:
        membership = GroupMembership.objects.get(user_id=user, group_id=group)
        return membership.status == MembershipStatus.Member or membership.status == MembershipStatus.Owner
    except ObjectDoesNotExist as dne:
        # if there is no record the user is not in the group
        return False


def is_group_owner(user, group):
    try:
        membership = GroupMembership.objects.get(user_id=user, group_id=group)
        return membership.status == MembershipStatus.Owner
    except ObjectDoesNotExist as dne:
        # if there is no record the user is not in the group and cannot be an owner
        return False


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


def equivalent_permission(p1: GroupKafkaPermission, 
                          p2: GroupKafkaPermission) -> bool:
    return p1.principal==p2.principal \
           and p1.topic==p2.topic \
           and p1.operation==p2.operation


def addKafkaPermissionForGroup(group_id: str, topic: KafkaTopic, operation: KafkaOperation):
    group = Group.objects.get(id=group_id)
    new_record = GroupKafkaPermission(principal=group, topic=topic, operation=operation)
    
    # look up all permissions for this group/topic combination to figure out if the new record is 
    # redundant or some old ones need to be replaced
    existing = GroupKafkaPermission.objects.filter(principal=group_id, topic=topic.id)
    
    if len(existing)>0:
        if any(equivalent_permission(p, new_record) for p in existing):
            # the exact permission we're trying to create already exists, 
            # so we can do nothing and declare success
            return
        if len(existing)==1 and existing[0].operation==KafkaOperation.All:
            # the existing permission is broader than the one being added,  
            # so we do not need to actually add it
            return
        if operation==KafkaOperation.All:
            # the new permission will supercede all existing permissions, so we remove them
            for old in existing:
                old.delete()
    
    # any possible redundancy being resolved, we can now create the actual record
    new_record.save()


def removeKafkaPermissionForGroup(permission: GroupKafkaPermission, owning_group_id: str=None) -> bool:
    if owning_group_id is None:
        topic = permission.topic
        owning_group_id = topic.owning_group
    if permission.principal == owning_group_id: # refuse to take away access from the owning group
        return False
    permission.delete()
    return True
    

class CredentialKafkaPermission(models.Model):
    principal = models.ForeignKey(
        SCRAMCredentials,
        on_delete=models.CASCADE,
    )
    # individual crentials derive their permissions from group permissions, 
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
    return str(parent_id)+cred_perm_encoding_separator+str(topic_id)+cred_perm_encoding_separator+str(operation)


# returns tuples of (parent ID, topic ID, operation type)
def decode_cred_permission(encoded: str):
    pattern = re.compile("([^"+cred_perm_encoding_separator+"]+)"+cred_perm_encoding_separator+"([^"+cred_perm_encoding_separator+"]+)"+cred_perm_encoding_separator+"([^"+cred_perm_encoding_separator+"]+)")
    match = re.fullmatch(pattern, encoded)
    if match is None or len(match.groups())!=3:
        raise ValueError("Invalid encoded credential permission")
    try:
        op = KafkaOperation[match[3]]
    except KeyError:
        raise ValueError("Invalid encoded credential permission")
    return (match[1],match[2],op)


# determine whether credential permission can be validly derived from the given group permission
def supportingPermission(group_perm,cred_perm):
    if cred_perm.topic != group_perm.topic:
        return False
    return group_perm.operation == KafkaPermission.All \
      or cred_perm.operation == group_perm.operationt


# returns tuples of (parent ID, topic ID, topic name, perm type)
def all_permissions_for_user(user):
    possible_permissions = []
    for membership in user.groupmembership_set.all():
        group = membership.group
        group_permissions = GroupKafkaPermission.objects.filter(principal=group).select_related('topic')
        for permission in group_permissions:
            if permission.operation==KafkaOperation.All:
                for subpermission in KafkaOperation.__members__:
                    possible_permissions.append((permission.id,permission.topic.id,permission.topic.name,subpermission))
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
    
    # lack of an obvious analogue to std::unique makes this awkward, and not in-place
    dedup = []
    last = None
    for p in possible_permissions:
        if last is None or not equivalent(last,p):
            dedup.append(p)
            last=p
    
    return dedup
                    
