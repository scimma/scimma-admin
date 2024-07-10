from django.core.exceptions import SuspiciousOperation, PermissionDenied
from mozilla_django_oidc import auth
from django.contrib import messages
import logging
import secrets
from django.conf import settings
from .models import sync_mailing_list_membership


logger = logging.getLogger(__name__)

class NotInKafkaUsers(PermissionDenied):
    pass


class HopskotchOIDCAuthenticationBackend(auth.OIDCAuthenticationBackend):
    """Subclass Mozilla's OIDC Auth backend for custom hopskotch behavior. """

    def __init__(self):
        auth.OIDCAuthenticationBackend.__init__(self)
        self.kafka_user_auth_group = settings.KAFKA_USER_AUTH_GROUP

    def filter_users_by_claims(self, claims):
        username = self.get_username(claims)
        if not username:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(username=username)

    def get_username(self, claims):
        return claims.get("sub")

    def get_email(self, claims):
        email = ""
        if "email" in claims:
            email = claims.get("email")
        elif "email_list" in claims:
            email = claims.get("email_list")

        if isinstance(email, list):
            email = email[0]
        return email

    def verify_claims(self, claims):
        logger.info(f"all claims: {claims}")
        if "is_member_of" not in claims:
            log_event_id = secrets.token_hex(8)
            msg = f"Your account is missing LDAP claims. Are you sure you used the account you use for SCIMMA? Error ID: {log_event_id}"
            logger.error(f"account is missing LDAP claims, error_id={log_event_id}, claims={claims}")
            raise PermissionDenied(msg)

        for group in [self.kafka_user_auth_group]:
            if not is_member_of(claims, group):
                name = claims.get('name', 'Unknown')
                id = claims.get('sub', 'Unknown')
                email = claims.get('email', 'Unknown')
                msg = f"User vo_display_name={name}, vo_person_id={id}, email={email} is not in {group}, but requested access"
                logger.error(msg)
                raise NotInKafkaUsers(msg)

        if "email" in claims:
            return True
        if "email_list" in claims and len(claims.get("email_list", [])) > 0:
            return True

        log_event_id = secrets.token_hex(8)
        msg = f"Your account is missing an email claim. Error ID: {log_event_id}"
        logger.error(f"account is missing LDAP email claims, error_id={log_event_id}, claims={claims}")
        raise PermissionDenied(msg)

    def create_user(self, claims):
        return self.UserModel.objects.create(
            username=self.get_username(claims),
            email=self.get_email(claims),
            is_staff=is_member_of(claims, '/SCiMMA Developers'),
            first_name=claims.get('given_name', ''),
            last_name=claims.get('family_name', ''),
        )

    def update_user(self, user, claims):
        user.first_name = claims.get('given_name', '')
        user.last_name = claims.get('family_name', '')
        user.email = self.get_email(claims)
        user.is_staff = is_member_of(claims, '/SCiMMA Developers')
        user.save()
        
        # Putting this here is a bit of a hack, and slows down the login process, but
        # deals with the case of a user's mailing list membership being altered externally.
        # Doing this once on login is a trade-off, as it will miss external changes while
        # the user is logged in, but avoids making repeated external requests
        sync_mailing_list_membership(user, settings.OPENMMA_MAILINGLIST)

        return user


def is_member_of(claims, group):
    logger.info(f"all claims: {claims}")
    return group in claims.get('is_member_of', [])
