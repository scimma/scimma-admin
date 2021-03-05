from django.core.exceptions import SuspiciousOperation, PermissionDenied
from mozilla_django_oidc import auth
from django.contrib import messages
import logging
import secrets
from django.conf import settings


logger = logging.getLogger(__name__)

class NotInKafkaUsers(PermissionDenied):
    pass


class HopskotchOIDCAuthenticationBackend(auth.OIDCAuthenticationBackend):
    """Subclass Mozilla's OIDC Auth backend for custom hopskotch behavior. """

    def __init__(self):
        auth.OIDCAuthenticationBackend.__init__(self)
        self.kafka_user_auth_group = settings.KAFKA_USER_AUTH_GROUP

    def filter_users_by_claims(self, claims):
        username = claims.get("vo_person_id")
        if not username:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(username=username)

    def get_username(self, claims):
        return claims.get("vo_person_id")

    def verify_claims(self, claims):
        logger.info(f"all claims: {claims}")
        if "is_member_of" not in claims:
            log_event_id = secrets.token_hex(8)
            msg = f"Your account is missing LDAP claims. Are you sure you used the account you use for SCIMMA? Error ID: {log_event_id}"
            logger.error(f"account is missing LDAP claims, error_id={log_event_id}, claims={claims}")
            raise PermissionDenied(msg)

        for group in [self.kafka_user_auth_group]:
            if not is_member_of(claims, group):
                name = claims.get('vo_display_name', 'Unknown')
                id = claims.get('vo_person_id', 'Unknown')
                email = claims.get('email', 'Unknown')
                msg = f"User vo_display_name={name}, vo_person_id={id}, email={email} is not in {group}, but requested access"
                logger.error(msg)
                raise NotInKafkaUsers(msg)

        return super(HopskotchOIDCAuthenticationBackend, self).verify_claims(claims)

    def create_user(self, claims):
        email = claims.get("email")
        if isinstance(email, list):
            claims["email"] = email[0]

        self.UserModel.objects.create(
            username=claims["vo_person_id"],
            email=claims["email"],
            is_staff=is_member_of(claims, 'CO:COU:SCiMMA DevOps:members:active'),
        )


def is_member_of(claims, group):
    logger.info(f"all claims: {claims}")
    return group in claims.get('is_member_of', [])
