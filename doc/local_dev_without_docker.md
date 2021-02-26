# An alternate guide to running SCiMMA-Admin for local development

This guide is an alternative to the recommendations in the top-level README for developing in Docker. This can be advantageous for more rapid iteration and greater ease of interfacing with other components. 

Running the scimma-admin application locally without docker requires installing the application itself in a suitable python environment, supplying it with a PostgeSQL database where it can store its state, and a small trick to spoof user identification data in order to create test users to work with. 


## Installing scimma-admin itself

Clone the code from Github:

	git clone https://github.com/scimma/scimma-admin

The main README says to use docker/docker-compose to run the application locally. This will _work_ but is not suitable for development for a couple of reasons: It is much more awkward to rapidly start and stop the service to test changes (the docker image must be rebuilt after every change), the partial isolation from the host's networking makes it harder to inject test user data (this would have to be added to the docker-compose configuration, with another container, which should be doable, but would require further work to figure out how), and on a non-Linux host this requires the overhead of running a the Docker Linux VM. Avoiding Docker requires additional up-front work, but allows for much faster iteration and seamless development. 

To run scimma-admin without a Docker container, a suitable python environment is required. One can create a virtual environment sharing the same directory:

	python3 -m venv .
	. bin/activate
	pip install -r requirements.txt

Adjust paths accordingly if you choose to keep your virtual environment in some other directory. 

The main README says to use scimma-aws-utils to download the necessary CILogon secret. A simpler alternative is to just run:

	export AWS_ACCESS_KEY_ID=<your scimma dev AWS ID>
	export AWS_SECRET_ACCESS_KEY=<your scimma dev AWS key>
	export AWS_DEFAULT_REGION=us-west-2
	make localdev.conf

This only needs to be done a single time; scimma-admin never otherwise needs access to any AWS credentials. 


## Setting up a backing database

There are two options for setting up a backing database--installed postgres, and docker:

### Using installed postgres

Not using the docker-compose configuration means that you must run PostgreSQL database yourself. This is not complicated. First, you will need to have postgres installed. It can just complied and installed it from source, but you should also be able to install it from a package manager. 

Once you have it installed, the database must be initialized. Like the python environment; this can be put in the scimma-admin directory as well to keep it self-contained, but you can put it anywhere you want. 

	initdb -D $(pwd)/dbdata
	pg_ctl -D $(pwd)/dbdata -l pg_logfile start
	psql postgres

This will put you in the postgresql management shell. In the lines below `postgres=#` is the prompt; you should enter only the part which follows it as a command. 

	postgres=# CREATE ROLE postgres;
	postgres=# ALTER ROLE postgres WITH PASSWORD 'postgres';
	postgres=# ALTER ROLE postgres LOGIN;
	postgres=# exit

The database itself is now running and ready for django to use. Django itself requires one additional setup step:

	python scimma_admin/manage.py migrate

This creates the database tables in the form django expects to use. 

### Using a dockerized postgres

To use a dockerized postgres, create a docker container using the postgres image:

	docker create --name scimma-admin-postgres -e POSTGRES_DB=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres -p 5432:5432 postgres

Then bring up the database:

	docker start scimma-admin-postgres

The database itself is now running and ready for django to use. Django itself requires one additional setup step:

	python scimma_admin/manage.py migrate

This creates the database tables in the form django expects to use. 


## Running the application itself

Note: any changes to `scimma-admin/settings.py` are unnecessary if you're using `local_settings.py`.

In order to make the application connect to the local database, not a docker container, one small change is required. In scimma-admin/settings.py, apply the following patch (currently the line to be changed is 133):

	--- scimma_admin/scimma_admin/settings.py
	+++ scimma_admin/scimma_admin/settings.py
	@@ -130,7 +130,7 @@ else:
	         'NAME': 'postgres',
	         'USER': 'postgres',
	         'PASSWORD': 'postgres',
	-        'HOST': 'db',
	+        'HOST': 'localhost',
	         'PORT': 5432,
	     }

The application can finally be started with `uwsgi`. You can run it on any port you want, but binding to port 80 requires superuser privileges, so it's usually easier to just use a higher numbered port, in this case 8000:

	uwsgi --chdir=scimma_admin --module=scimma_admin.wsgi:application \
	--env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
	--pidfile=project-master.pid --http :8000 --processes 1 --threads 2

This will run in the foreground, taking over your terminal window. It can be stopped with Ctrl-C. If you change any python scripts, you will need to stop and restart `uwsgi`, but changes to the HTML templates do not require a restart, simply reloading the page should be sufficient. 


## Accessing the web interface

Once you have the application running, you should be able to view its interface by opening http://127.0.0.1:8000/hopauth in your web browser. About the only thing you should see will be the 'Login' link. If this shows up everything is working, but there is one more key step to do before logging in.

In order to test out being different users, for example an admin user or a regular user, it's useful to replace the data scimma-admin would normally fetch from COmanage via CILogon with data of your own choosing. 

First, kill `uwsgi`. Next, make another small change to scimma_admin/settings.py:

	--- scimma_admin/scimma_admin/settings.py
	+++ scimma_admin/scimma_admin/settings.py
	@@ -139,7 +139,8 @@ else:
	 # https://mozilla-django-oidc.readthedocs.io/en/stable/settings.html
	 OIDC_OP_AUTHORIZATION_ENDPOINT = 'https://cilogon.org/authorize/'
	 OIDC_OP_TOKEN_ENDPOINT = 'https://cilogon.org/oauth2/token'
	-OIDC_OP_USER_ENDPOINT = 'https://cilogon.org/oauth2/userinfo'
	+OIDC_OP_USER_ENDPOINT = 'http://localhost:8001'
	+OIDC_VERIFY_SSL = False
	 OIDC_RP_SIGN_ALGO = 'RS256'
	 OIDC_OP_JWKS_ENDPOINT = 'https://cilogon.org/oauth2/certs'
	 AUTHENTICATION_BACKENDS = (

This will instruct it after a user authenticates via CILogon to fetch the user's information from a local port (and not to require that connection to be authenticated/encrypted with TLS). 

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

Now, start a second terminal window in the same directory, and use netcat to serve the pre-written HTTP response on port 8001, where scimma-admin will shortly ask for it: 

	nc -l 8001 < user_data_test-admin

This will tie up that terminal window until a client has connected and gotten the document from netcat. 

Now, in your first window, start `uwsgi` again:

	uwsgi --chdir=scimma_admin --module=scimma_admin.wsgi:application \
	--env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
	--pidfile=project-master.pid --http :8000 --processes 1 --threads 2

and return to http://127.0.0.1:8000/hopauth . You may want to do this is private browsing window, so that you can do this multiple times as different made-up users. This time, click the 'Login' link, select your institution from the CILogon list, and log in with your institutional credentials. 

Sometimes the application is a bit squirrelly at this point, and after completing the log-in process you will be sent to a page which just says 'OK'. If this happens, just change the URL back to http://127.0.0.1:8000/hopauth and log in again; some of the process will probably be skipped because you have already done so and the results are stored in your browser session. 

When you are in, you should see the main Hopauth page, with the user email address mentioned at the top being the one you put in the file being served by netcat (`test-admin@example.com`) instead of your own institutional email address. 

Note that one disadvantage of netcat is that it will serve the file exactly once, and then exit, so each time you log in again with a new browser session, you will need to run it again. 

If you want to make up additional test users, just create more files similar to `user_data_test-admin` and serve the one you want to use with `nc` just before logging in to use it. When doing this note that you should change the `vo_person_id` to be distinct for each user, and give each user a unique email address. You will probably also want to set the `vo_display_name`s to be different, although scimma-admin will not  To make a non-admin user, omit the `"CO:COU:SCiMMA DevOps:members:active",` line from the `is_member_of` list. 


## Shutting down

When you're done with all of this, simply kill `uwsgi` with Ctrl-C if it was running, and instruct postgres to shut down:

	pg_ctl -D $(pwd)/dbdata -l pg_logfile stop

If you're using a dockerized postgres:

	docker stop scimma-admin-postgres


## Starting back up

Very little of the setup work needs to be repeated; it should be sufficient to reenter your virtual environment, start postgres, and start `uwsgi`:

	. bin/activate
	pg_ctl -D $(pwd)/dbdata -l pg_logfile start
	uwsgi --chdir=scimma_admin --module=scimma_admin.wsgi:application \
	--env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
	--pidfile=project-master.pid --http :8000 --processes 1 --threads 2

If you're using dockerized postgres, you should run `docker start scimma-admin-postgres` in lieu of `pg_ctl ...`

Don't forget to run netcat to impersonate whichever test user you want before each time you log in to the web interface. 