from abc import ABC, abstractmethod, abstractclassmethod, abstractproperty

class ConnectionInterface(ABC):
    @abstractmethod
    def new_credential(self, username, description):
        pass
    
    @abstractmethod
    def delete_credential(self, username, cred_name):
        raise NotImplementedError()
    
    @abstractmethod
    def get_credential_permissions(self, username, cred_name):
        raise NotImplementedError()
    
    @abstractmethod
    def add_permission(self, username, cred_name, group, topic, permission):
        raise NotImplementedError()
    
    @abstractmethod
    def remove_permission(self, username, cred_name, group, topic, permission):
        raise NotImplementedError()
    
    @abstractmethod
    def suspend_credential(self, username, cred_name):
        raise NotImplementedError()
    
    @abstractmethod
    def create_group(self, username, group_name, description):
        raise NotImplementedError()
    
    @abstractmethod
    def delete_group(self, username, group_name):
        raise NotImplementedError()
    
    @abstractmethod
    def add_topic_to_group(self, username, group_name, topic_name, permission):
        raise NotImplementedError()
    
    @abstractmethod
    def remove_topic_from_group(self, username, group_name, topic_name, permission):
        raise NotImplementedError()
    
    @abstractmethod
    def create_topic(self, username, group_name, topic_name):
        raise NotImplementedError()
    
    @abstractmethod
    def delete_topic(self, username, group_name, topic_name):
        raise NotImplementedError()
    
    @abstractmethod
    def add_topic_permission(self, username, topic_name, permission):
        raise NotImplementedError()
    
    @abstractmethod
    def remove_topic_permission(self, username, topic_name, permission):
        raise NotImplementedError()
    
    @abstractmethod
    def get_all_user_permissions(self, username):
        raise NotImplementedError()
    
    @abstractmethod
    def get_credential_info(self, username):
        raise NotImplementedError()
    
    @abstractmethod
    def get_user_credentials(self, username):
        raise NotImplementedError()

    @abstractmethod
    def get_user_topics(self, username):
        raise NotImplementedError()
    
    @abstractmethod
    def get_user_groups(self, username):
        raise NotImplementedError()