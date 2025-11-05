
##
## This file is an overall configuration file for scimmma_adim
## it is meant to be sourced, and supoport shell scripts
## drive lall  server development environments. 
##
## Suporting postigras datasnes (archivne and scimma daming)
## may be local or accessed via a tunnel. 
##
## CI (COnfuguratin itme) names engin wih r SECTERT_NAME or DB_NAME 
## -l  Configure for local scimma_admin database, no archive databse
## -d  Configure for access to AWS-resident development archive and admin databases. 
## -p  Configure for access to AWS-resident producti0on archive and admin databases. 

Help() {
    echo "-prod or dev or local"  >&2
    return 1
}

# purge local variables.
cleanup () { unset system }
trap cleanup  EXIT INT TERM ERR

# require argments
if [ $# -eq 0 ]; then
    echo Arguements required >&2
    Help
    return 1
fi

# Parse options
system=$1
if [[ "$system" == "prod" || "$system" == "dev" || "$system" == "local" ]]; then
    echo configuring for system $system
else
    Help
    return 1
fi
# ensure all options are processed
shift
if [ $# -gt 0 ]; then
    echo "Error: Unrecognized arguments: $@" >&2
    Help
    return 1
fi

##
## Core DJANGO
##

#settings.py Name : DEBUG
#CI_Name          : DJANGO_DEBUG
#What is it       : the overall python logging level for DJOAN
#Why Config       : debug can be useful in development, DEBUG must not be used in prod.
#normal Default   : INFO
export DJANGO_DEBUG=INFO

#aettings.py name : SECRET_KEY
#CI_Name          : SECRET_KEY_SECRET_NAME
#What is it       : A secret used internally by django to encrypt things.
#Why Config       : prod and dev deployment get the secret key  from AWS
#Why Config       : LOCAL_DEV just makes one up ("zzzlocal") as its' transient.
export SECRET_KEY_=zzzlocal


##
## Sympa Related
##

#settings.py Name : SYMPA_CREDS
#CI_Name          : SYMPA_CREDS_SECRET_NAME
#What is it       : credentials to access SYMPA.
#What is it       : ALSO  flag indicating to not activate ...
#What is it       : sympa access IF SET TO {}
#terraform?       : scimma_admin.tf "scimma_admin_sympa_secret"
#Why Config       : to indeicate whther to access SYMPA.
#Overrride        : use  SYMPA_SECRET_KEY_SECRET_NAME from env populate
SYMPA_CREDS={}

##
## Databases 
##

#settings.py Name : DATABASES
#CI_Name          : as below
# What is it      : information needed to connect to scimma_admin and archive databases.
# Why Config      : dev and prod deployments require differnet databases.
# Why Config      : Tunnel based development needs to access the prod and devel DBS.
# Why Config      : Advancement of the scimma_admin schema is done on local postgress schema.
# Default         : None Must be set via command line

echo "$system"

if [ "$system" = "prod" ]; then
    echo "environment configured for tunneling to prod databases"
    export ARCHIVE_HOST="scotch.prod.hop.scimma.org"
    export ARCHIVE_DB_INSTANCE_NAME=hopprod-archive-ingest-db
    export ARCHIVE_DB_SECRET_NAME=hopProd-archive-ingest-db-password
    export ARCHIVE_DNS=hopprod-archive-ingest-db.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    
    export ADMIN_HOST="scotch.prod.hop.scimma.org"
    export ADMIN_DNS=prod-scimma-admin-postgres.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    export ADMIN_DB_INSTANCE_NAME=prod-scimma-admin-postgres
    export ADMIN_DB_SECRET_NAME=prod-scimma-admin-db-password
elif [ "$system" = "dev" ]; then
    echo "environment configured for tunneling to dev databases"
    export ARCHIVE_HOST="scotch.dev.hop.scimma.org"
    export ARCHIVE_DNS=hopdevel-archive-ingest-db.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    export ARCHIVE_DB_INSTANCE_NAME=hopdevel-archive-ingest-db
    export ARCHIVE_DB_SECRET_NAME=hopDevel-archive-ingest-db-password

    export ADMIN_HOST="scotch.dev.hop.scimma.org"
    export ADMIN_DNS=scimma-admin-postgres.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    export ADMIN_DB_INSTANCE_NAME=scimma-admin-postgres
    export ADMIN_DB_SECRET_NAME=scimma-admin-db-password
else
    export ARCHIVE_DNS="127.0.0.1"
    export ARCHIVE_DB_INSTANCE_NAME=pastgres
    export ARCHIVE_DB_SECRET_NAME=hopDevel-archive-ingest-db-password

    export ADMIN_DNS="127.0.0.1"
    export ADMIN_DB_INSTANCE_NAME=scimma-admin-postgres
    export ADMIN_DB_SECRET_NAME=scimma-admin-db-password

fi


##
## Auth related
##

# Settings.py name: SECURE_SSL_REDIRECT
#CI_Name          : SECURE_SSL_REDIRECT 
#What is it : causes django re redirecet http to https automaticalls. 
#Why Config : Some development is simpler of done on http, to avoind the work of setting u  https stuff.
export SECURE_SSL_REDIRECT=false

# Settings.py name : :KAFKA_USER_AUTH_GROUP
# CI_Name          : KAFKA_USER_AUTH_GROUP
# What is it       : The name of the group in Keycloak that idenfies users authorized to use HOP. 
# Why Config       : dunno we have one keycloak and apparently one group shared between dev and prod
# Override         : Value of env variable KAFKA_USER_AUTH_GROUP 
#Assert            : None
export KAFKA_USER_AUTH_GROUP="/Hopskotch Users"

# Settings.py name : KAFKA_BROKER_URL
# CI_Name          : KAFKA_BROKER_URL
# What is it : The URL to a kafka Broker 
# Why Config : dev and prod use different instances (what about Localdev??)
# Override   : Value of env variable KAFKA_BROKER_URL 
# Assert     : is not None in Prod, dev.
export KAFKA_BROKER_URL=dog

# Settings.py name : OIDC_RP_CLIENT_ID
# CI_Name          : OIDC_RP_CLIENT_ID
# What is it : A client provided by the OIDC Provider
#terraform? : scimma_admin.tf: "scimma_admin_keycloak_client_id"
export OIDC_RP_CLIENT_ID=dog

# Settings.py name : OIDC_RP_CLIENT_SECRET
# CI_Name          : OIDC_RP_CLIENT_SECRET_NAME
# What is it : A secrert to access the OIDC provider, given a CLIENT_ID
# Why Config : TBD
# terraform? : scimma_admin.tf "scimma_admin_keycloak_client_secret"
# terraform? : scimma_admin.tf "cilogon_localdev_client_secret"
export OIDC_RP_CLIENT_SECRET_NAME=dog




