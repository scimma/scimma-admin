from abc import ABC, abstractmethod, abstractclassmethod, abstractproperty
from typing import Any, Dict, List, Set, Tuple
from .result import Result

from .models import *

class ConnectionInterface(ABC):
    @abstractmethod
    def new_credential(self, username: str, description: str) -> Result[Dict[str, str], str]:
        pass
    
    @abstractmethod
    def delete_credential(self, username: str, cred_name: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def get_credential_permissions(self, username: str, cred_name: str) -> Result[List[CredentialKafkaPermission], str]:
        raise NotImplementedError()
    
    @abstractmethod
    def add_credential_permission(self, username: str, cred_name: str, group_name: str, topic_name: str, permission: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def remove_credential_permission(self, username: str, cred_name: str, group_name: str, topic_name: str, permission: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def suspend_credential(self, username: str, cred_name: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def unsuspend_credential(self, username: str, cred_name: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def create_group(self, username: str, group_name: str, description: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def delete_group(self, username: str, group_name: str) -> Result[None, str]:
        raise NotImplementedError()

    @abstractmethod
    def add_member_to_group(self, group_name: str, username: str, status_name: str) -> Result[None, str]:
        raise NotImplementedError()

    @abstractmethod
    def remove_member_from_group(self, group_name: str, username: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def create_topic(self, username: str, group_name: str, topic_name: str, description: str, publicly_readable: bool) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def delete_topic(self, username: str, group_name: str, topic_name: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def add_group_topic_permission(self, username: str, group_name: str, topic_name: str, permission: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def remove_group_topic_permission(self, username: str, group_name: str, topic_name: str, permission: str) -> Result[None, str]:
        raise NotImplementedError()
    
    @abstractmethod
    def get_credential(self, username: str, cred_name: str) -> Result[SCRAMCredentials, str]:
        raise NotImplementedError()

    @abstractmethod
    def get_user_credentials(self, username: str) -> Result[List[SCRAMCredentials], str]:
        raise NotImplementedError()

    @abstractmethod
    def get_user_accessible_topics(self, username: str) -> Result[List[Tuple[KafkaTopic, str]], str]:
        raise NotImplementedError()

    @abstractmethod
    def get_user_group_memberships(self, username: str) -> Result[List[GroupMembership], str]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_users(self) -> Result[List[User], str]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_credentials(self) -> Result[List[SCRAMCredentials], str]:
        raise NotImplementedError()

    @abstractmethod
    def get_all_groups(self) -> Result[List[Group], str]:
        raise NotImplementedError()
