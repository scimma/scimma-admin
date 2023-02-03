from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers
from .models import *

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

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["pk", "username", "email"]
        read_only_fields = ["pk", "username", "email"]

class SCRAMCredentialsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SCRAMCredentials
        fields = ["pk", "owner", "username", "created_at", "suspended", "description"]
        read_only_fields = ["pk", "owner", "username", "created_at"]

class GroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ["pk", "name", "description"]
        read_only_fields = ["pk", "name"]
		
class GroupMembershipSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupMembership
        fields = ["pk", "user", "group", "status"]
        read_only_fields = ["pk", "user", "group"]
    status = ReadableEnumField(MembershipStatus)

class GroupMembershipCreationSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupMembership
        fields = ["user", "group", "status"]
    status = ReadableEnumField(MembershipStatus)

class KafkaTopicSerializer(serializers.ModelSerializer):
    class Meta:
        model = KafkaTopic
        fields = ["pk", "owning_group", "name", "publicly_readable", "description", "archivable",
                  "max_message_bytes", "retention_ms", "retention_bytes"]
        read_only_fields = ["pk", "owning_group", "name",
                            "max_message_bytes", "retention_ms", "retention_bytes"]

    def validate_publicly_readable(self, value):
        if value is not True:
            raise serializers.ValidationError("Public topics may not be made private")

class KafkaTopicAdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = KafkaTopic
        fields = ["pk", "owning_group", "name", "publicly_readable", "description", "archivable",
                  "n_partitions", "max_message_bytes", "retention_ms", "retention_bytes"]
        read_only_fields = ["pk", "owning_group", "name"]

class KafkaTopicCreationSerializer(serializers.ModelSerializer):
    class Meta:
        model = KafkaTopic
        fields = ["owning_group", "name", "publicly_readable", "description"]

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
        fields = ["pk", "principal", "topic", "operation"]
        read_only_fields = ["pk", "principal", "topic", "operation"]
    operation = ReadableEnumField(KafkaOperation)

class GroupKafkaPermissionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = GroupKafkaPermission
        fields = ["principal", "topic", "operation"]
    operation = ReadableEnumField(KafkaOperation)
		
class CredentialKafkaPermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CredentialKafkaPermission
        fields = ["pk", "principal", "topic", "operation"]
        read_only_fields = ["pk", "principal", "topic", "operation"]
    operation = ReadableEnumField(KafkaOperation)
    
class CredentialKafkaPermissionCreationSerializer(serializers.ModelSerializer):
    class Meta:
        model = CredentialKafkaPermission
        fields = ["principal", "topic", "operation"]
    operation = ReadableEnumField(KafkaOperation)
