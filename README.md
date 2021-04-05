# scimma-admin

This is a web tool for managing access to SCIMMA's Hopskotch system. The main
deployment of it is at
[https://admin.dev.hop.scimma.org/hopauth/](https://admin.dev.hop.scimma.org/hopauth/).
At that URL, you can create, list, and revoke credentials which are used to
access Hopskotch's Kafka system. For more information on usage, see [the
guide](./doc/hopauth_guide.md).

## Design

The original design document is [on Google
Docs](https://docs.google.com/document/d/108v71YY9JJmfnY74IKPgHV5LXB6cxlKsTMdBq6zAJSs/edit).

At a high level: users authenticate against [the SCIMMA COManage
Registry](https://registry.scimma.org/registry/co_dashboards/dashboard/co:2) to
prove their identity. They can then generate credentials, which are held only in
memory; a hash of the credentials is stored in a Postgres database.
Asynchronously, these hashes are loaded into Kafka's backend so they can be used
by clients. Here's a diagram:

![diagram](./doc/hopauth_design.png)]

### Design: Authentication

scimma-admin authenticates users through an [OIDC](https://openid.net/connect/)
flow. The details of this are mostly handled by the third-party
[mozilla-django-oidc](https://mozilla-django-oidc.readthedocs.io/en/stable/)
plugin. However, a few details get custom behavior, which is implemented in a
[HopskotchOIDCAuthenticationBackend
class](./scimma_admin/hopskotch_auth/auth.py):
  - Users must be connected to LDAP (if this is not the case, it's probably a
    bug in COManage)
  - Users must be in the `SCiMMA Institute Active Members` COManage group
  - Users must be in the `kafkaUsers` COManage group

User uniqueness is maintained by using their `vo_person_id` value from COManage.

### Design: Credential Generation

Once a user has authenticated, they get access to the [credential management
tools](./scimma_admin/hopskotch_auth/views.py). The most important of these is
credential generation. This is implemented in the `new_credentials` method in
[`hopskotch_auth/models.py`](./scimma_admin/hopskotch_auth/models.py).

Usernames and passwords are generated automatically, with no user input. We do
this because:
 1. This way, all usernames are guaranteed to be unique.
 2. Nobody can impersonate other people with usernames - you can't create an
    account named 'swnelson' and do something nefarious.
 3. People can't use weak passwords which are crackable.
 4. People can't reuse passwords they use everywhere else, so we don't need to
    worry about password leaks on other sites.

Usernames are derived from a user's email address with a random suffix. Email
addresses might be a little nonunique, but they're more human-readable than
truly unique options like the `vo_person_id` field. The password is 32 random
characters.

Once a password is generated, it is only held in memory. Instead of storing the
password, we store a derived bundle of hashes, following [RFC 5802: Salted
Challenge Response Authentication Mechanism
(SCRAM)](https://tools.ietf.org/html/rfc5802) with the SHA-512 algorithm and
4096 hash iterations. This credential bundle is stored in a SQL database which
is managed with Django's ORM.

### Design: Infrastructure

scimma-admin is deployed on SCIMMA's Kubernetes cluster on AWS. Its
infrastructure is managed with Terraform through the
[aws-dev](https://github.com/scimma/aws-dev/blob/master/tf/eksDeployments/scimma-admin.tf)
repository. It relies on the presence of a Postgres database for storing
credentials.

Most of the machinery for the Kubernetes deployment is handled with the
[terraform-kubernetes-service](https://github.com/scimma/terraform-kubernetes-httpservice/)
module. This module uses HTTP health checks, so the root URL returns a plain
"OK" message too indicate it's healthy.

All credentials used in production are managed with AWS Secrets Manager. They're
loaded directly in [the Django `settings.py`
file](./scimma_admin/scimma_admin/settings.py).



## Developer Guide

### Local Development: prerequisites

You'll need AWS credentials. Install
[`scimma-aws`](https://github.com/scimma/scimma-aws-utils) first.

If you will develop on Windows OS, you will have issues with uWSGI package in requirements.txt. You can remove it and download uwsgi.exe. For running makefiles on Windows, you will need to download MinGW (the easy way) or Cygwin.

### Local Development: first-time setup

Run `make localdev-setup`. This will download a few secrets from AWS, which will
let you communicate with CILogon, even locally.

Next, start up the database. This can be done either with a Docker container, or by running the database directly on the host system. The former requires Docker, while the latter requires PostgresQL.

To use Docker, run

    python scripts/create_db.py --with-docker

or to use postgres directly, run

    python scripts/create_db.py --dbdata dbdata

Once it's up and running, run a database migration to prep the DB. You only need
to do this on first-time setup, and then whenever the DB schema is changed.

    python scimma_admin/manage.py migrate

Similarly, initialize static files used by the application. This is only needed at first-time 
setup or when new assets are added. 

    python scimma_admin/manage.py collectstatic

Finally, start the service itself:

    ./scripts/run_local

You can then go to `http://127.0.0.1/hopauth/` to open the website locally.

To shut down the service, press Ctrl-C to end `uwgi`/`run_local`. 
If you are running the database without Docker, you may want to stop it as well with `pg_ctl -D dbdata stop`. If you want to resume work again, you can then restart it with `pg_ctl -D dbdata -l pg_logfile start`. 
Likewise, if using Docker, you can stop your database with `docker stop scimma-admin-postgres` and later restart it with `docker start scimma-admin-postgres`. 

### Local Development: running tests

To run the tests, with your database running, run this command:

    cd scimma_admin; python manage.py test; cd -

### Local Development: Impersonating a different user

When developing, it is often useful to be able to change user identities, such as switching 
between admin and non-admin user profiles. This can be accomplished by replacing the 
data scimma-admin would normally fetch from COmanage via CILogon with data of your 
own choosing. User identities created in this way will exist only in your local database, as 
production deployments will only fetch user data from the official CILogon source. 

To change how user data is fetched, create a local setting file:

    cp scimma_admin/sample_local_settings.py scimma_admin/local_settings.py

and then edit it to include:

    OIDC_OP_USER_ENDPOINT = 'http://localhost:8001'
    OIDC_VERIFY_SSL = False

This will instruct it after a user authenticates via CILogon to fetch the user's information 
from a local port (and not to require that connection to be authenticated/encrypted with TLS).

Next, create some user data to serve: Make a text file named `user_data_test-admin`, and give it the following contents:

    HTTP/1.1 200 OK
    Content-Type: application/json;charset=UTF-8
    Connection: close

    {
      "sub": "http://cilogon.org/serverA/users/22753625",
      "email_list": [
        "test-admin@example.com"
      ],
      "iss": "https://cilogon.org",
      "vo_person_id": "SCiMMA2000002",
      "is_member_of": [
        "CO:members:all",
        "SCiMMA Institute Members",
        "CO:members:active",
        "CO:COU:SCiMMA DevOps:members:active",
        "SCiMMA Institute Active Members",
        "kafkaUsers"
      ],
      "email": "test-admin@example.com",
      "vo_display_name": "test-admin"
    }

Finally, start a second terminal window in the same directory, and use netcat to serve the 
pre-written HTTP response on port 8001, where scimma-admin will shortly ask for it: 

    nc -l 8001 < user_data_test-admin

This will tie up that terminal window until a client has connected and gotten the document from netcat. 

When you are log into the application again, you should see the main Hopauth page, with the user email address mentioned at the top being the one you put in the file being served by netcat (`test-admin@example.com`) instead of your own institutional email address. 

Note that one disadvantage of netcat is that it will serve the file exactly once, and then exit, so each time you log in again with a new browser session, you will need to run it again. 

If you want to make up additional test users, just create more files similar to `user_data_test-admin` and serve the one you want to use with `nc` just before logging in to use it. When doing this note that you should change the `vo_person_id` to be distinct for each user, and give each user a unique email address. You will probably also want to set the `vo_display_name`s to be different, although scimma-admin will not  To make a non-admin user, omit the `"CO:COU:SCiMMA DevOps:members:active",` line from the `is_member_of` list.

### Deploying a new version

This project is deployed on SCIMMA's Kubernetes cluster through
https://github.com/scimma/aws-dev. To deploy a new version, you have to build
the docker container, push it to our container registry, and then update the
Kubernetes cluster. You can do this all in one pass by running [`./scripts/deploy/do_deploy.sh`](./scripts/deploy/do_deploy.sh).

Check the logs of your deployment with this:
```
kubectl logs -f -l appName=hopdevel-scimma-admin
```
