from django.core.management import BaseCommand
from rest_authtoken.models import AuthToken, EmailConfirmationToken
from django.utils import timezone
from scimma_admin.settings import DATABASES
from hopskotch_auth.models import RESTAuthToken, SCRAMExchange



class Command(BaseCommand):
    help = 'Delete all expired auth tokens and SCRAM exchanges'

    # This re-implements the functionality of django-rest-authtoken's clearexpiredauthtokens,
    # but in a way which avoids problems with https://code.djangoproject.com/ticket/27813#comment:7
    # when using PostgreSQL as the database backend.
    # If that bug is ever fixed, the direct use of psycopg2 here should be removed.
    def clear_expired_authtokens(self) -> int:
        if not "default" in DATABASES:
            self.stderr.write("default database not configured")
            return
        database = DATABASES["default"]
        if "ENGINE" not in database or database["ENGINE"] != "django.db.backends.postgresql":
        	self.stderr.write("default database not configured")
        	return

        import psycopg2

        valid_min_creation = timezone.now() - AuthToken.TOKEN_VALIDITY
        to_delete = AuthToken.objects.filter(created__lt=valid_min_creation)
        base_table_name = AuthToken._meta.db_table
        derived_table_name = RESTAuthToken._meta.db_table

        # connect directly to the database to delete without Django foolishness happening
        conn = psycopg2.connect(host=database.get("HOST", None),
                                port=database.get("PORT", 5432),
                                dbname=database.get("NAME", None),
                                user=database.get("USER", None),
                                password=database.get("PASSWORD", None))
        with conn:
            with conn.cursor() as curs:
                for token in to_delete:
                    curs.execute(f"DELETE FROM {derived_table_name} WHERE authtoken_ptr_id = %s",
                                 (psycopg2.Binary(token.hashed_token),))
                    curs.execute(f"DELETE FROM {base_table_name} WHERE hashed_token = %s",
                                 (psycopg2.Binary(token.hashed_token),))
        conn.close()
        return len(to_delete)

    def handle(self, *args, **options):
        deleted_tokens = self.clear_expired_authtokens()
        self.stdout.write(f"Removed {deleted_tokens} expired auth token(s)")
        deleted_exchanges = SCRAMExchange.clear_expired()
        self.stdout.write(f"Removed {deleted_tokens} expired SCRAM exchange(s)")