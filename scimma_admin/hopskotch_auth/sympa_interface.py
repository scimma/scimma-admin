from dataclasses import dataclass
from django.conf import settings
from suds.client import Client
from typing import List

class SympaClientBase:
    def __init__(self, wsdl_url):
        self.client = Client(wsdl_url)
    
    def begin_session(self):
        pass
    
    def end_session(self):
        pass
    
    class Session:
        def __init__(self, client):
            self.client = client
        
        def __enter__(self):
            self.client.begin_session()
            return self.client
        
        def __exit__(self, *args):
            self.client.end_session()
    
    def session(self):
        return self.Session(self)

class IndividualClient(SympaClientBase):
    def __init__(self, type: str, wsdl_url: str, email: str, password: str):
        assert type == "individual"
        self.email = email
        self.password = password
        self.cookie = None
        super().__init__(wsdl_url)
    
    def begin_session(self):
        self.cookie = self.client.service.login(self.email, self.password)
        
    def request(self, service: str, args: List[str]):
        assert self.cookie
        return self.client.service.authenticateAndRun(self.email, self.cookie, service, args)

class ApplicationClient(SympaClientBase):
    def __init__(self, type: str, wsdl_url: str, name: str, password: str, variables: str = ""):
        assert type == "application"
        self.name = name
        self.password = password
        self.variables = variables
        super().__init__(wsdl_url)
        
    def request(self, service: str, args: List[str]):
        assert self.cookie
        return self.client.service.authenticateRemoteAppAndRunRequest(
               self.name, self.password, self.variables, service, args)

soap_clients = {}
for domain, settings in settings.SYMPA_CREDS.items():
    if settings["type"] == "individual":
        soap_clients[domain] = IndividualClient(**settings)
    elif settings["type"] == "application":
        soap_clients[domain] = ApplicationClient(**settings)
    else:
        raise ValueError("Invalid sympa authentication type: "+settings["type"])

def check_user_list_subscription(email: str, list_addr: str) -> bool:
    bare_name, domain = list_addr.split('@')
    if domain not in soap_clients:
        raise ValueError("No configuration available for mailing list "+list_addr)
    with soap_clients[domain].session() as client:
        return client.request("amI", [list_addr,"subscriber",email])

def subscribe_user_to_list(email: str, list_addr: str, username: str = ""):
    bare_name, domain = list_addr.split('@')
    if domain not in soap_clients:
        raise ValueError("No configuration available for mailing list "+list_addr)
    with soap_clients[domain].session() as client:
        subscribed = client.request("amI", [list_addr,"subscriber",email])
        if subscribed:
            return  # no futher action required
        subscribed = client.request("add", [list_addr,email,username,True])
        if not subscribed:
            raise RuntimeError("Unable to subscribe "+email+" to "+list_addr)

def unsubscribe_user_from_list(email: str, list_addr: str):
    bare_name, domain = list_addr.split('@')
    if domain not in soap_clients:
        raise ValueError("No configuration available for mailing list "+list_addr)
    with soap_clients[domain].session() as client:
        subscribed = client.request("amI", [list_addr,"subscriber",email])
        if not subscribed:
            return  # no futher action required
        unsubscribed = client.request("del", [list_addr,email,True])
        if not unsubscribed: # TODO: is this condition right?
            raise RuntimeError("Unable to unsubscribe "+email+" from "+list_addr)
