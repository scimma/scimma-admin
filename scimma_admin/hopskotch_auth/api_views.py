import datetime
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import F, Q
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
import rest_authtoken.auth
import rest_authtoken.models
import scramp
import logging

from .models import *
from .serializers import *
from .views import client_ip

logger = logging.getLogger(__name__)

class scram_first(APIView):
    authentication_classes = []

    def post(self, request):
        if "client_first" not in request.data:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
        client_first = request.data["client_first"]
        
        # all credentials we issue are SHA-512
        s = scramp.ScramMechanism("SCRAM-SHA-512").make_server(scram_user_lookup)
        try:
            s.set_client_first(client_first)
            logger.info(f"Began a SCRAM exchange for user {s.user} from {client_ip(request)}")
        
            # If scramp did not complain, the exchange can proceed. 
            # First, we record the state so that it can be picked up later.
            ex = SCRAMExchange()
            ex.cred = SCRAMCredentials.objects.get(username=s.user)
            ex.j_nonce = s.nonce
            ex.s_nonce_len = len(s.s_nonce)
            ex.client_first = client_first
            ex.began = datetime.datetime.now(datetime.timezone.utc)
            ex.save()

            # Then, we can send the challenge back to the client
            return Response(data={"server_first": s.get_server_first()}, status=status.HTTP_200_OK)
        except ValueError:
            logger.info(f"Rejected invalid SCRAM request (first) from {client_ip(request)}")
            return Response(data={"error": "Invalid SCRAM request"},
                            status=status.HTTP_401_UNAUTHORIZED)
        except (ObjectDoesNotExist, scramp.ScramException):
            # Authentication has failed, likely due to a malformed SCRAM message, or an unknown
            # username being claimed
            logger.info(f"Rejected invalid SCRAM request (first) from {client_ip(request)}")
            return Response(data={"error": "Invalid SCRAM request", 
                                  "server_final": s.get_server_final()}, 
                            status=status.HTTP_401_UNAUTHORIZED)

class scram_final(APIView):
    authentication_classes = []
    
    def post(self, request):
        if "client_final" not in request.data:
            return Response(status=status.HTTP_400_BAD_REQUEST)

        client_final = request.data["client_final"]

        # a bit ugly: To find the previously started exchange session, if any, we need to extract
        # the nonce from the request. We can either reimplement the parsing logic, or underhandedly
        # reach inside of scramp to use its parse function. We do the latter.
        parsed = scramp.core._parse_message(client_final)
        if not 'r' in parsed:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        try:
            ex = SCRAMExchange.objects.get(j_nonce=parsed['r'])
        except ObjectDoesNotExist:
            logger.info(f"Rejected invalid SCRAM request (final) from {client_ip(request)}; "
                        "Exchange invlid or expired")
            # We have no record of this SCRAM exchange. Either it timed out or was never begun.
            return Response(status=status.HTTP_400_BAD_REQUEST)

        try:
            # recreate the SCRAM server state from our stored exchange record
            s = scramp.ScramMechanism("SCRAM-SHA-512").make_server(scram_user_lookup, 
                                                                   s_nonce=ex.s_nonce())
            s.set_client_first(ex.client_first)
            s.get_server_first()  # waste of time, but scramp requires this to be called
            # if we reach this point, we are ready to process the second half of the exchange
            s.set_client_final(client_final)
            # if scramp hasn't objected, the authentication has now succeeded
            
            # Issue a short-lived REST token
            token = rest_authtoken.models.AuthToken.create_token_for_user(ex.cred.owner)

            # Return to the client the SCRAM server final message, the issued token, and
            # expiration time of the token
            expire_time = rest_authtoken.models.AuthToken.get_token(token).created \
                        + settings.REST_TOKEN_TTL
            data = {
                "server_final": s.get_server_final(),
                "token": base64.urlsafe_b64encode(token),
                "token_expires": expire_time
            }
            logger.info(f"Issued REST token to user {ex.cred.username} "
                        f"with expiration time {expire_time}")
            return Response(data=data, status=status.HTTP_200_OK)
        except ValueError:
            logger.info(f"Rejected invalid SCRAM request (final) from {client_ip(request)}")
            return Response(data={"error": "Invalid SCRAM request"},
                            status=status.HTTP_401_UNAUTHORIZED)
        except (ObjectDoesNotExist, scramp.ScramException):
            # Authentication has failed
            logger.info(f"Rejected invalid SCRAM request (final) from {client_ip(request)}")
            return Response(data={"error": "Invalid SCRAM request", 
                                  "server_final": s.get_server_final()}, 
                            status=status.HTTP_401_UNAUTHORIZED)
        finally:
            ex.delete()  # clean up the exchange session record

class token_for_oidc_user(APIView):
    authentication_classes = [rest_authtoken.auth.AuthTokenAuthentication]
    # TODO !!! must also have special authority to use this privileged feature
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def post(self, request):
        if "vo_person_id" not in request.data:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        username = request.data["vo_person_id"]
        
        try:
            user = User.objects.get(username=username)
            
            # Issue a short-lived REST token
            token = rest_authtoken.models.AuthToken.create_token_for_user(user)

            # Return to the client the the issued token and expiration time of the token
            expire_time = rest_authtoken.models.AuthToken.get_token(token).created \
                        + settings.REST_TOKEN_TTL
            data = {
                "token": base64.urlsafe_b64encode(token),
                "token_expires": expire_time
            }
            logger.info(f"Issuing a REST token to {request.user.username} ({request.user.email}) "
                        f"at {client_ip(request)} "
                        f"to act on behalf of {user.username} (user.email)")
            return Response(data=data, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response(data={"error": "Invalid user ID"},
                            status=status.HTTP_401_UNAUTHORIZED)
        

class UserViewSet(viewsets.ModelViewSet):
    authentication_classes = [rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    queryset = User.objects.all()
    serializer_class = UserSerializer
    
    def list(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    "requested to list all users "
                    f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)
    
    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested information about user {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        # TODO: enable DCS creation of user records
        raise PermissionDenied

    def destroy(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        raise PermissionDenied

    
class SCRAMCredentialsViewSet(viewsets.ModelViewSet):
    authentication_classes = [rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = SCRAMCredentialsSerializer

    def get_queryset(self):
        queryset = SCRAMCredentials.objects.all()
        
        # if specified, pull out only the credentials belonging to a specific user
        if "user" in self.kwargs:
            owner = self.kwargs["user"]

            # non-staff users may not view other users' credentials
            if not self.request.user.is_staff and owner!=self.request.user.id:
                raise PermissionDenied

            queryset = queryset.filter(owner=owner)

        else: # only staff members may see the full, unfiltered list
            if not self.request.user.is_staff:
                raise PermissionDenied

        return queryset

    def list(self, request, *args, **kwargs):
        if "user" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list SCRAM credentials belonging to user {kwargs['user']} "
                    f"from {client_ip(request)}")
        else:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                        "requested to list SCRAM credentials belonging to all users "
                        f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of SCRAM credential {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        bundle = new_credentials(request.user)
        
        logger.info(f"Created new credential {bundle.username} on behalf of user "
                f"{request.user.username} ({request.user.email}) from {client_ip(request)}")
        
        try:
            if "description" in request.data:
                bundle.creds.description = request.data["description"]
                bundle.creds.save()
        except:
            logger.info(f"Failed to set SCRAM credential description")
        
        data = {
            "username": bundle.username,
            "password": bundle.password
        }
        
        return Response(data=data, status=status.HTTP_201_CREATED)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to delete SCRAM credential {kwargs.get('cred','<missing>')} "
                    f"from {client_ip(request)}")
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        raise PermissionDenied

class GroupViewSet(viewsets.ModelViewSet):
    authentication_classes = [rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    # all users are allowed to see the full list of groups
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    
    def list(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    "requested to list all groups "
                    f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of group {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to create a group "
                    f"from {client_ip(request)}")
        # only staff should create groups
        if not self.request.user.is_staff:
                raise PermissionDenied
        return super().create(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to delete group {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        # only staff should delete groups
        if not self.request.user.is_staff:
                raise PermissionDenied
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        raise PermissionDenied

class GroupMembershipViewSet(viewsets.ModelViewSet):
    authentication_classes = [rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    serializer_class = GroupMembershipSerializer

    def get_queryset(self):
        queryset = GroupMembership.objects.all()
        # if specified, pull out only the memberships of a specific user
        if "user" in self.kwargs:
            target_user = self.kwargs["user"]
            
            # non-staff users may not view other users' group memberships
            if not self.request.user.is_staff and target_user!=self.request.user.id:
                raise PermissionDenied

            queryset = queryset.filter(user=target_user)

        # if specified, pull out only the memberships of a specific group
        if "group" in self.kwargs:
            group = self.kwargs["group"]
            
            # non-staff members may not examine the membership lists of groups to which they do not belong
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, group):
                raise PermissionDenied
            
            queryset = queryset.filter(group=group)

        # only staff members may see the full, unfiltered list
        if not self.request.user.is_staff and "user" not in self.kwargs and "group" not in self.kwargs:
            raise PermissionDenied
            
        return queryset

    def list(self, request, *args, **kwargs):
        if "user" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list user {kwargs['user']}'s group memberships "
                    f"from {client_ip(request)}")
        elif "group" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list group {kwargs['group']}'s memberships "
                    f"from {client_ip(request)}")
        else:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                        "requested to list all group memberships "
                        f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of group membership {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to add a permission to SCRAM credential {kwargs.get('cred','<missing>')} "
                    f"from {client_ip(request)}")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        group = serializer.validated_data['group']
        target_user = serializer.validated_data['user']
        
        # Only admins and group owners can change group memberships
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, group.id):
            raise PermissionDenied
        
        # Forbid creation of redundant enries
        if is_group_member(target_user.id, group.id):
            raise BadRequest(f"User {target_user} is already a member of group {group}")
        
        membership = serializer.save()
        
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to remove permission {kwargs.get('pk','<missing>')} "
                    f"from SCRAM credential {kwargs.get('cred','<missing>')} "
                    f"from {client_ip(request)}")
        instance = self.get_object()
        
        # Only admins and group owners can change group memberships
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, instance.group.id):
            raise PermissionDenied
        
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
        
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to update group {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        instance = self.get_object()
        # Only admins and group owners can change group memberships
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, instance.group.id):
            raise PermissionDenied
        
        return super().partial_update(request, *args, **kwargs)
    
    def partial_update(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to update group {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        instance = self.get_object()
        # Only admins and group owners can change group memberships
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, instance.group.id):
            raise PermissionDenied
        
        # avoid invoking the overridden self.update and making logging confusing
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

class KafkaTopicViewSet(viewsets.ModelViewSet):
    authentication_classes = [rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    serializer_class = KafkaTopicSerializer
    
    def get_queryset(self):
        queryset = KafkaTopic.objects.all()
        
        # if specified, pull out only the topics owned by a specific group
        if "owning_group" in self.kwargs:
            group = self.kwargs["owning_group"]

            # non-staff users may not generally view topics owned by groups to which they do not belong
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, group):
                raise PermissionDenied
            
            queryset = queryset.filter(owning_group=group)

        elif not self.request.user.is_staff:
            # non-staff users can only see topics to which they have been granted access
            # this includes topics which are public, 
            # and topics for which access has been granted to a group to which the user belongs.
            public_topics = KafkaTopic.objects.filter(publicly_readable=True)
            #TODO: figure out how to implement selection of topics for which access is granted to a 
            #group to which the requesting user belongs
            #accessible_topics = 
            
            
            queryset = public_topics
            
        return queryset

    def list(self, request, *args, **kwargs):
        if "owning_group" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list topics owned by group {kwargs['owning_group']} "
                    f"from {client_ip(request)}")
        else:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                        "requested to list all Kafka topics "
                        f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of Kafka topic {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        if "owning_group" not in self.kwargs:
            raise PermissionDenied  # TODO: might want to use a more generic invalid request
        
        group_id = self.kwargs["owning_group"]
        
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to create a Kafka topic owned by group {group_id} "
                    f"from {client_ip(request)}")
        
        try:
            group = Group.objects.get(id=group_id)
        except ObjectDoesNotExist as dne:
            raise PermissionDenied  # TODO: more correct error
        
        # non-staff users may not create topics owned by groups of which they are not owners
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, group.id):
            raise PermissionDenied
        
        data = request.data
        data["owning_group"] = group.id

        serializer = KafkaTopicCreationSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        with transaction.atomic():
            topic = serializer.save()
            GroupKafkaPermission.objects.create(principal=group, topic=topic, operation=KafkaOperation.All)
        return_serializer = self.get_serializer(topic)
        headers = self.get_success_headers(return_serializer.data)
        return Response(
            return_serializer.data, status=status.HTTP_201_CREATED, headers=headers
        )

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to delete Kafka topic {kwargs.get('pk','<missing>')} "
                    f"owned by group {kwargs.get('owning_group','<unknown>')} "
                    f"from {client_ip(request)}")
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to update Kafka topic {kwargs.get('pk','<missing>')} "
                    f"owned by group {kwargs.get('owning_group','<unknown>')} "
                    f"from {client_ip(request)}")
        instance = self.get_object()
        # Only admins and group owners can change topics
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, instance.group.id):
            raise PermissionDenied
        
        return super().partial_update(request, *args, **kwargs)
    
    def partial_update(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to update Kafka topic {kwargs.get('pk','<missing>')} "
                    f"owned by group {kwargs.get('owning_group','<unknown>')} "
                    f"from {client_ip(request)}")
        instance = self.get_object()
        # Only admins and group owners can change topics
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, instance.group.id):
            raise PermissionDenied
        
        # avoid invoking the overridden self.update and making logging confusing
        kwargs['partial'] = True
        return super().update(request, *args, **kwargs)

class GroupKafkaPermissionViewSet(viewsets.ModelViewSet):
    authentication_classes = [rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = GroupKafkaPermissionSerializer

    def get_queryset(self):
        queryset = GroupKafkaPermission.objects.all()
        all = True
        
        # if specified, pull out permissions granted by the specified group
        if "granting_group" in self.kwargs:
            group = self.kwargs["granting_group"]
            
            # non-staff users may not query the full set of permissions granted by groups
            # to which they do not belong
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, group):
                raise PermissionDenied
            
            queryset = queryset.filter(topic__owning_group=group)
            all = False
        
        # if specified, pull out permissions granted by the specified group
        if "subject_group" in self.kwargs:
            group = self.kwargs["subject_group"]
            
            # non-staff users may not query the full set of permissions granted to groups
            # to which they do not belong
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, group):
                raise PermissionDenied
            
            queryset = queryset.filter(principal=group)
            all = False
            
        # if specified, pull out permissions relating to the specified topic
        if "topic" in self.kwargs:
            topic_id = self.kwargs["topic"]
            # TODO: is it okay to let ObjectDoesNotExist propagate from here?
            topic = KafkaTopic.objects.get(id=topic_id)
            
            # non-staff users may not query the full set of permissions to a topic if they do not
            # belong to the group which owns it
            if not self.request.user.is_staff and not is_group_member(self.request.user.id, topic.owning_group):
                raise PermissionDenied
            
            queryset = queryset.filter(topic=topic)
            all = False
            
        # only staff members may see the unrestricted list
        if all and not self.request.user.is_staff:
            raise PermissionDenied
            
        return queryset

    def list(self, request, *args, **kwargs):
        msg = f"User {request.user.username} ({request.user.email}) " \
              "requested to list group permissions "
        if "granting_group" in kwargs:
            msg += f" granted by group {kwargs['granting_group']}"
        if "subject_group" in kwargs:
            msg += f" granted to group {kwargs['subject_group']}"
        if "topic" in kwargs:
            msg += f" associated with topic {kwargs['topic']}"
        msg += f"from {client_ip(request)}"
        logger.info(msg)
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of group permission {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to create a group permission "
                    f"from {client_ip(request)}")
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        topic = serializer.validated_data['topic']
        
        # Only admins and group owners can change group memberships
        if not self.request.user.is_staff and not is_group_owner(self.request.user.id, topic.owning_group):
            raise PermissionDenied
        
        perm = add_kafka_permission_for_group(serializer.validated_data['principal'].id,
                                              serializer.validated_data['topic'],
                                              serializer.validated_data['operation'])
        
        # the result object may not be exactly the one requested, so re-serialize explicitly
        result_data = self.get_serializer(perm).data
        headers = self.get_success_headers(result_data)
        return Response(result_data, status=status.HTTP_201_CREATED, headers=headers)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to remove group permission {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        # TODO: enforce access rules
        
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        raise PermissionDenied

class CredentialKafkaPermissionViewSet(viewsets.ModelViewSet):
    authentication_classes = [rest_authtoken.auth.AuthTokenAuthentication]
    permission_classes = [IsAuthenticated]

    serializer_class = GroupKafkaPermissionSerializer

    def get_queryset(self):
        queryset = CredentialKafkaPermission.objects.all()
        
        if "cred" in self.kwargs:
            cred_id = self.kwargs["cred"]
            # TODO: is it okay to let ObjectDoesNotExist propagate from here?
            cred = SCRAMCredentials.objects.get(id=cred_id)
            
            # non-staff users may not query the properties of credentials they do not own
            if not self.request.user.is_staff and cred.owner!=self.request.user:
                raise PermissionDenied
            
            queryset = queryset.filter(principal=cred)
        elif not self.request.user.is_staff:
            # only staff users may query the full list
            raise PermissionDenied
        
        return queryset
        
    def list(self, request, *args, **kwargs):
        if "cred" in kwargs:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to list permissions attatched to SCRAM credential {kwargs['cred']} "
                    f"from {client_ip(request)}")
        else:
            logger.info(f"User {request.user.username} ({request.user.email}) "
                        "requested to list all SCRAM credential permissions "
                        f"from {client_ip(request)}")
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested the details of SCRAM credential permission {kwargs.get('pk','<missing>')} "
                    f"from {client_ip(request)}")
        return super().retrieve(request, *args, **kwargs)

    def create(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to add a permission to SCRAM credential {kwargs.get('cred','<missing>')} "
                    f"from {client_ip(request)}")
        # TODO: enforce access rules
        
        return super().create(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        logger.info(f"User {request.user.username} ({request.user.email}) "
                    f"requested to remove permission {kwargs.get('pk','<missing>')} "
                    f"from SCRAM credential {kwargs.get('cred','<missing>')} "
                    f"from {client_ip(request)}")
        # TODO: enforce access rules
        
        return super().destroy(request, *args, **kwargs)
    
    def update(self, request, *args, **kwargs):
        raise PermissionDenied
    
    def partial_update(self, request, *args, **kwargs):
        raise PermissionDenied