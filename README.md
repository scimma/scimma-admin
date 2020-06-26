# scimma-admin

## Local Development: first-time setup

Start up the service by using `docker-compose`:
```
docker-compose up
```

Once it's up and running, run a database migration to prep the DB. You only need
to do this on first-time setup, and then whenever the DB schema is changed.

```
docker-compose exec django python manage.py migrate
```

Next, create a superuser.
```
docker-compose exec django python manage.py createsuperuser
```

Follow the prompts to create a username and password.

You can then go to `http://127.0.0.1:8000/admin/` to open the web-based
administrative tools. Log in with the superuser account you created, and you can
'Add' more test users if you like.

You can log out, and log in as users at http://127.0.0.1:8000/admin/login. Don't
try to go straight to http://127.0.0.1:8000/hopauth/ without being logged in, or
you'll get an error because the local development server isn't set up to handle
SCIMMA authentication.
