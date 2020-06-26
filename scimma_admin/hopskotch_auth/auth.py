from django.core.exceptions import SuspiciousOperation
from mozilla_django_oidc import auth
import logging

logger = logging.getLogger(__name__)

class HopskotchOIDCAuthenticationBackend(auth.OIDCAuthenticationBackend):
    """Subclass Mozilla's OIDC Auth backend for custom hopskotch behavior. """

    def filter_users_by_claims(self, claims):
        email = claims.get("email")
        if isinstance(email, list):
            claims["email"] = email[0]
        return super(HopskotchOIDCAuthenticationBackend, self).filter_users_by_claims(claims)

    def get_username(self, claims):
        return claims['vo_display_name']

    def verify_claims(self, claims):
        logger.info(f"all claims: {claims}")
        for group in ['kafkaUsers', 'SCiMMA Institute Active Members']:
            if not is_member_of(claims, group):
                name = claims.get('vo_display_name', 'Unknown')
                id = claims.get('vo_person_id', 'Unknown')
                email = claims.get('email', 'Unknown')
                logger.error(f"User vo_display_name={name}, vo_person_id={id}, email={email} is not in {group}, but requested access")
                return False
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
