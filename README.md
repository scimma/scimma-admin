# scimma-admin

## Local development: prerequisites

You'll need AWS credentials. Install
[`scimma-aws`](https://github.com/scimma/scimma-aws-utils) first.

If you will develop on Windows OS, you will have issues with uWSGI package in requirements.txt. You can remove it and download uwsgi.exe. For running makefiles on Windows, you will need to download MinGW (the easy way) or Cygwin.

## Local Development: first-time setup

Run `make localdev-setup`. This will download a few secrets from AWS, which will
let you communicate with CILogon, even locally.

Start up the service by using `docker-compose`:
```
docker-compose up
```

Once it's up and running, run a database migration to prep the DB. You only need
to do this on first-time setup, and then whenever the DB schema is changed.

```
docker-compose exec django python manage.py migrate
```

You can then go to `http://127.0.0.1/hopauth/` to open the website locally.

## Local Development: running tests

With your service up and running in a terminal (with `docker-compose up`), open
a new terminal. Run this:

```
docker-compose exec django python manage.py test
```
