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

        def failWithError(user_msg, log_msg):
            log_event_id = secrets.token_hex(8)
            user_msg += f" Error ID: {log_event_id}"
            log_msg += f", error_id={log_event_id}"
            logger.error(log_msg)
            self.request.session["login_failure_reason"] = user_msg
            raise PermissionDenied(user_msg)

        if "is_member_of" not in claims or "vo_person_id" not in claims:
            failWithError("Your identity is missing LDAP claims. "
                          "Are you sure you used the account you use for SCIMMA?",
                          f"account is missing LDAP claims, claims={claims}"
                          )

        for group in [self.kafka_user_auth_group]:
            if not is_member_of(claims, group):
                name = claims.get('vo_display_name', 'Unknown')
                id = claims.get('vo_person_id', 'Unknown')
                email = claims.get('email', 'Unknown')
                failWithError(f"Your account is not a member of the {group} group "
                              "and so is not authorized to access Hopskotch",
                              f"User vo_display_name={name}, vo_person_id={id}, "
                              "email={email} is not in {group}, but requested access")

        if "email" in claims:
            return True
        if "email_list" in claims and len(claims.get("email_list", [])) > 0:
            return True

        failWithError("Your account is missing an email claim.",
                      f"account is missing LDAP email claims, claims={claims}")

    def create_user(self, claims):
        if "email" in claims:
            email = claims.get("email")
        elif "email_list" in claims:
            email = claims.get("email_list")

        if isinstance(email, list):
            email = email[0]

        return self.UserModel.objects.create(
            username=claims["vo_person_id"],
            email=email,
            is_staff=is_member_of(claims, 'CO:COU:SCiMMA DevOps:members:active'),
        )


def is_member_of(claims, group):
    logger.info(f"all claims: {claims}")
    return group in claims.get('is_member_of', [])
