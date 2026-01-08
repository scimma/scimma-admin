import boto3
import os
import json

##
## Configuration suppport section 
##


CI_LOG={}  # log config actions here


def get_literal_ci(item_name):
    value  = os.getenv(item_name)
    CI_LOG[item_name] = value
    return value

def get_aws_db_info_ci(db_instance_ci):
    """
    Return a dictionary with database info in the format
    DJANGO expects.


    Populate the structure with information from AWS.
    https://docs.djangoproject.com/en/3.0/ref/settings/#databases
    """
    db_instance_id  = os.getenv(db_instance_ci)
    print ("************************", db_instance_ci, db_instance_id, "****************")

    # make an (mostly) empty template
    database_cv  = {
        "ENGINE" : "django.db.backends.postgresql"
    }
    
    # fillout from AWS if the item_name is a defined environment variable
    rds = boto3.client("rds", region_name="us-west-2")
    rds_db = rds.describe_db_instances(
        Filters=[{"Name": "db-instance-id", "Values": [db_instance_id]},]
    )
    rds_db = rds_db["DBInstances"][0]
    database_cv["NAME"] = rds_db["DBName"]
    database_cv["USER"] = rds_db["MasterUsername"]
    database_cv["HOST"] = rds_db["Endpoint"]["Address"]
    database_cv["PORT"] = rds_db["Endpoint"]["Port"]

    return database_cv

def get_aws_secret_ci(secret_ci):
    name = os.getenv(secret_ci)
    if not name : return name
    print ("************************", secret_ci, name, "****************")
    sm = boto3.client("secretsmanager", region_name="us-west-2")
    secret_cv = sm.get_secret_value(SecretId=name)["SecretString"]
    return secret_cv

def cv_to_bool(cv):
    if cv.lower() in ["true", "yes", "on", "1"]:
        return True
    if cv.lower() in ["false", "yes", "on", "1"]:
        return False
    raise RuntimeError(f"bad value for {name}: {str}")
    CI_LOG[name] = cv

    
###
###  configuration override section 
###
    
DATABASES = {}

DATABASES["archive"] = get_aws_db_info_ci("ARCHIVE_DB_INSTANCE_NAME")
DATABASES["archive"]["PORT"]     = get_literal_ci("ARCHIVE_TUNNEL_LOCAL_PORT")
DATABASES["archive"]["HOST"]     = get_literal_ci("ARCHIVE_TUNNEL_LOCAL_HOST")
DATABASES["archive"]["PASSWORD"] = get_aws_secret_ci("ARCHIVE_DB_PASSWORD_SECRET_NAME")

DATABASES["default"] = get_aws_db_info_ci("ADMIN_DB_INSTANCE_NAME")
DATABASES["default"]["PORT"]     = get_literal_ci("ADMIN_TUNNEL_LOCAL_PORT")
DATABASES["default"]["HOST"]     = get_literal_ci("ADMIN_TUNNEL_LOCAL_HOST")
DATABASES["default"]["PASSWORD"] = get_aws_secret_ci("ADMIN_DB_PASSWORD_SECRET_NAME") 



# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

### settings.py name : SECRET_KEY
### CI_Name(aws)     : SECRET_KEY_SECRET_NAME
### CI_Name(literal)): SECRET_KEY
### What is it       : A secret used internally by django to encrypt things.
### Why Config       : prod and dev deployment get the secret key  from AWS
### Why Config       : LOCAL_DEV just makes one up ("zzzlocal") as its' transient.
### SECURITY WARNING: keep the secret key used in production secret!
if cv :=  get_aws_secret_ci("SECRET_KEY_SECRET_NAME"): SECRET_KEY = cv
if cv := get_literal_ci("SECRET_KEY") : SECRET_KEY = cv


###settings.py Name : SYMPA_CREDS
###CI_Name(aws)     : SYMPA_CREDS_SECRET_NAME
###CI_Name(literal) : SYMPA_CREDS
####What is it      : credentials to access SYMPA.
###What is it       : ALSO  flag indicating to not activate ...
###What is it       : ... sympa access IF SET TO {}
### Why Config      : to indicate whther to access SYMPA.
### WHy Config      : To authenticate to Symps 

if cv := get_aws_secret_ci("SYMPA_CREDS_SECRET_NAME") : SYMPA_CREDS = json.loads(cv)
if cv := get_literal_ci("SYMPA_CREDS") : SYMPA_CREDS = json.loads(cv)

### Settings.py name: SECURE_SSL_REDIRECT
### CI_Name          : SECURE_SSL_REDIRECT 
### What is it : causes django to redirect http to https automatically if true. 
### Why Config : Some development is simpler if done on http, to avoind the work of setting https stuff.
if cv := get_literal_ci("SECURE_SSL_REDIRECT") : SECURE_SSL_REDIRECT = cv_to_bool(cv)

### settings.py Name : DEBUG
### CI_Name          : DJANGO_DEBUG
### What is it       : true-> DEBUG  false -> INFO
### Why Config       : debug can be useful in development, DEBUG must not be used in prod.
### Normal Default   : INFO
### SECURITY WARNING: don't run with debug turned on in production!
if cv := get_literal_ci("DJANGO_DEBUG"): DJANGO_DEBUG = cv_to_bool(cv)

### Settings.py name : OIDC_OP_USER_ENDPOINT
### CI_NAME          : OIDC_OP_USER_ENDPOINT
### What is it       : WHere Django goes to fetch "CLAIMS" about a user to compare...
### What is it       : given the "identiy" provided when it was a Op_CLIENT..
### Why config       : we want production database for AWS  but...
### Why config       : we want to simulate this in local for developement flex...
### Why config       : e.g spoof uses, invistiagate new claims etc.  e.g. poor man's dev keycloak.
### Example setting  : 'https://login.scimma.org/realms/SCiMMA/protocol/openid-connect/userinfo'
### Example setting  : (bypass keycloak for local dev) http://localhost:8001'
if cv := get_literal_ci("OIDC_OP_USER_ENDPOINT") : OIDC_OP_USER_ENDPOINT = cv

### Settings.py name : OIDC_OP_CLIENT_ID
### CI_NAME          : OIDC_OP_CLIENT_ID_SECRET_NAME
### CI_NAME          : OIDC_OP_CLIENT_ID_SECRET_NAME
### What is it       : Identifies acimmm-admin app to the identity provider.
### Why config       : AWS inscalletion use keycloak 
### Why config       : For local devlepoemt no authentication is needed..
### Example setting  : 
if cv := get_aws_secret_ci('OIDC_OP_CLIENT_ID_SECRET_NAME') :
    OIDC_OP_CLIENT_ID = cv
if cv := get_literal_ci("OIDC_OP_CLIENT_ID") : OIDC_OP_CLIENT_ID = cv

### Settings.py name : OIDC_RP_CLIENT_ID
### CI_Name          : OIDC_RP_CLIENT_ID
### What is it : scimma-admin  app is a client to  OIDC provider...
### Example setting  : scimma-admin-keycloak-client-id"
### Example setting  : cilogon:/client_id/79be6fcf2057dbc381dfb8ba9c17d5fd'
if cv :=  get_literal_ci("OIDC_RP_CLIENT_ID") : OIDC_RP_CLIENT_ID = cv


### CI_Name(aws)      : OIDC_RP_CLIENT_SECRET_SECRET_NAME
### CI_Name(literal)  : OIDC_RP_CLIENT_SECRET
### What is it : A secret to access the OIDC provider specifed in client_id.
### Example setting  : scimma-admin-keycloak-client-secret
### Example setting  : scimma-admin-cilogon-localdev-client-secret
if cv := get_aws_secret_ci("OIDC_RP_CLIENT_SECRET_SECRET_NAME"):
        OIDC_RP_CLIENT_SECRET = cv  # talk to Chris.
if cv := get_literal_ci("OIDC_RP_CLIENT_SECRET") :
    OIDC_RP_CLIENT_SECRET = cv # talk to Chris.


### Settings.py name : KAFKA_USER_AUTH_GROUP
### CI_Name          : KAFKA_USER_AUTH_GROUP[
### What is it       : The name of the group in Key[cloak that idenfies users authorized to use HOP. 
### Why Config       : dunno we have one keycloak and apparently one group shared between dev and prod
if cv := get_literal_ci("KAFKA_USER_AUTH_GROUP") :
    KAFKA_USER_AUTH_GROUP = cv

### Settings.py name : KAFKA_BROKER_URL
### CI_Name          : KAFKA_BROKER_URL
### What is it : The URL to a kafka Broker 
### Why Config : dev and prod use different instances
### dev.hop.scimma.org or kafka.scimma.org for the AWS versions

if cv := get_literal_ci("KAFKA_BROKER_URL"):
    KAFKA_BROKER_URL = cv


### Settings.py name::  PRINT_CONFIG
### CI_Name          :  PRINT_CONFIG 
### What is it : Print all the CI's out  
### Why Config : control verbosity.
PRINT_CONFIG = cv_to_bool(get_literal_ci("PRINT_CONFIG"))
if PRINT_CONFIG :
    import pprint
    print('************************  Configuration report ****************')
    pprint.pp(DATABASES)
    pprint.pp(CI_LOG)
    print('************************  Configuration report ****************')

    

    
