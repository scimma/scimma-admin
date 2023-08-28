from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers
from ..models import *
from .v0 import UserSerializer, GroupSerializer

import traceback

class ReadableEnumField(serializers.Field):
    def __init__(self, enum_cls, *args, **kwargs):
        self.enum = enum_cls
        return super(ReadableEnumField, self).__init__(*args, **kwargs)

    def to_representation(self, value):
        return value.name

    def to_internal_value(self, value):
        # handle string values for enum member names
        if value in self.enum.__members__:
            return self.enum.__members__[value]
        # handle raw values (usually ints)
        if value in self.enum:
            return self.enum(value)
        raise serializers.ValidationError(f"Invalid membership status value {value}")

class PrettyForeignKeyField(serializers.Field):
    def __init__(self, target_model, to_key, *args, **kwargs):
        self.model_cls = target_model
        self.to_key = to_key
        return super(PrettyForeignKeyField, self).__init__(*args, **kwargs)

    def to_representation(self, value):
        return getattr(value, self.to_key)
        
    def to_internal_value(self, value):
        args = {self.to_key: value}
        return self.model_cls.objects.get(**args)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email"]
        read_only_fields = ["id", "username", "email"]

class SCRAMCredentialsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SCRAMCredentials
        fields = ["id", "owner", "username", "created_at", "suspended", "description"]
        read_only_fields = ["id", "owner", "username", "created_at"]
    owner = PrettyForeignKeyField(User, "username")

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ["id", "name", "description"]
        read_only_fields = ["id", "name"]

class GroupMembershipSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupMembership
        fields = ["id", "user", "group", "status"]
        read_only_fields = ["id", "user", "group"]
    user = PrettyForeignKeyField(User, "username")
    group = PrettyForeignKeyField(Group, "name")
    status = ReadableEnumField(MembershipStatus)

class GroupMembershipCreationSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupMembership
        fields = ["user", "group", "status"]
    user = PrettyForeignKeyField(User, "username")
    group = PrettyForeignKeyField(Group, "name")
    status = ReadableEnumField(MembershipStatus)

class KafkaTopicSerializer(serializers.ModelSerializer):
    class Meta:
        model = KafkaTopic
        fields = ["id", "owning_group", "name", "publicly_readable", "description", "archivable",
                  "max_message_bytes", "retention_ms", "retention_bytes"]
        read_only_fields = ["id", "owning_group", "name",
                            "max_message_bytes", "retention_ms", "retention_bytes"]

    owning_group = PrettyForeignKeyField(Group, "name")

    def validate_publicly_readable(self, value):
        if value is not True:
            raise serializers.ValidationError("Public topics may not be made private")

class KafkaTopicAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = KafkaTopic
        fields = ["id", "owning_group", "name", "publicly_readable", "description", "archivable",
                  "n_partitions", "max_message_bytes", "retention_ms", "retention_bytes"]
        read_only_fields = ["id", "owning_group", "name"]

    owning_group = PrettyForeignKeyField(Group, "name")

class KafkaTopicCreationSerializer(serializers.ModelSerializer):
    class Meta:
        model = KafkaTopic
        fields = ["owning_group", "name", "publicly_readable", "description"]

    owning_group = PrettyForeignKeyField(Group, "name")

    def validate(self, data):
        data = super().validate(data)
        
        name = data["name"]
        group = data["owning_group"]
        
        if not validate_topic_name(name):
            raise serializers.ValidationError("Invalid topic name")

        name = group.name + '.' + name
        
        if KafkaTopic.objects.filter(name=name).exists():
            raise serializers.ValidationError("Topic name already in use")
            
        data["name"] = name
        
        return data

class GroupKafkaPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupKafkaPermission
        fields = ["id", "principal", "topic", "operation"]
        read_only_fields = ["id", "principal", "topic", "operation"]
    principal = PrettyForeignKeyField(Group, "name")
    topic = PrettyForeignKeyField(KafkaTopic, "name")
    operation = ReadableEnumField(KafkaOperation)

class GroupKafkaPermissionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupKafkaPermission
        fields = ["principal", "topic", "operation"]
    principal = PrettyForeignKeyField(Group, "name")
    topic = PrettyForeignKeyField(KafkaTopic, "name")
    operation = ReadableEnumField(KafkaOperation)

class CredentialKafkaPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CredentialKafkaPermission
        fields = ["id", "principal", "topic", "operation"]
        read_only_fields = ["id", "principal", "topic", "operation"]
    principal = PrettyForeignKeyField(SCRAMCredentials, "username")
    topic = PrettyForeignKeyField(KafkaTopic, "name")
    operation = ReadableEnumField(KafkaOperation)

class CredentialKafkaPermissionCreationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CredentialKafkaPermission
        fields = ["principal", "topic", "operation"]
    principal = PrettyForeignKeyField(SCRAMCredentials, "username")
    topic = PrettyForeignKeyField(KafkaTopic, "name")
    operation = ReadableEnumField(KafkaOperation)
