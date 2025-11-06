
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

get_tunnel_info() {
    #Return the RDS json structure for DB instance passed in as $1
    aws rds describe-db-instances --db-instance-identifier "$1"  \
	       --query 'DBInstances[0]' \
	       --output json
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

# thsi might be a shim for integration.
export SCIMMA_ENVIRONMENT=system

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
    # settings.oy CIs (recall these are also terraform CIs)
    export ARCHIVE_DB_INSTANCE_NAME=hopprod-archive-ingest-db
    export ARCHIVE_DB_SECRET_NAME=hopProd-archive-ingest-db-password
    export ADMIN_DB_INSTANCE_NAME=prod-scimma-admin-postgres
    export ADMIN_DB_SECRET_NAME=prod-scimma-admin-db-password

    #tunnel support CIs (Nothing to do with terraform) 
    tunnel_info=$(get_tunnel_info $ARCHIVE_DB_INSTANCE_NAME)
    export ARCHIVE_TUNNEL_BASTION="scotch.prod.hop.scimma.org"
    export ARCHIVE_TUNNEL_REMOTE_HOST=$(echo $tunnel_info | jq -r '.Endpoint.Address')
    export ARCHIVE_TUNNEL_REMOTE_PORT=$(echo $tunnel_info | jq -r '.Endpoint.Port')
    export ARCHIVE_TUNNEL_LOCAL_PORT=54361
    tunnel_info=$(get_tunnel_info $ADMIN_DB_INSTANCE_NAME)
    export ADMIN_TUNNEL_BASTION="scotch.prod.hop.scimma.org"
    export ADMIN_TUNNEL_REMOTE_HOST=$(echo $tunnel_info | jq -r '.Endpoint.Address')
    export ADMIN_TUNNEL_REMOTE_PORT=$(echo $tunnel_info | jq -r '.Endpoint.Port')
    export ADMIN_TUNNEL_LOCAL_PORT=54361
    export ADMIN_DB_LOCAL_PORT=54360

elif [ "$system" = "dev" ]; then
    echo "environment configured for tunneling to dev databases"
    # settings.oy CIs (recall these are also terraform CIs)
    export ARCHIVE_DB_INSTANCE_NAME=hopdevel-archive-ingest-db
    export ARCHIVE_DB_SECRET_NAME=hopDevel-archive-ingest-db-password
    export ADMIN_DB_INSTANCE_NAME=scimma-admin-postgres
    export ADMIN_DB_SECRET_NAME=scimma-admin-db-password

    #tunnel support CIs (Nothing to do with terraform) 
    tunnel_info=$(get_tunnel_info $ARCHIVE_DB_INSTANCE_NAME)
    export ARCHIVE_TUNNEL_BASTION="scotch.dev.hop.scimma.org"
    export ARCHIVE_TUNNEL_REMOTE_HOST=$(echo $tunnel_info | jq -r '.Endpoint.Address')
    export ARCHIVE_TUNNEL_REMOTE_PORT=$(echo $tunnel_info | jq -r '.Endpoint.Port')
    export ARCHIVE_TUNNEL_LOCAL_PORT=54361
    tunnel_info=$(get_tunnel_info $ADMIN_DB_INSTANCE_NAME)
    export ADMIN_TUNNEL_BASTION="scotch.dev.hop.scimma.org"
    export ADMIN_TUNNEL_REMOTE_HOST=$(echo $tunnel_info | jq -r '.Endpoint.Address')
    export ADMIN_TUNNEL_REMOTE_PORT=$(echo $tunnel_info | jq -r '.Endpoint.Port')
    export ADMIN_TUNNEL_LOCAL_PORT=54361
else
    export ARCHIVE_DB__NAME=postgres
    export ARCHIVE_DB__USER=postgres
    export ARCHIVE_DB_PASSWORD=postgres
    export ARCHIVE_HOST="127.0.0.1"
    export ARCHIVE_DB_PORT=5436
    
    export ADMIN_DB__NAME=postgres
    export ADMIN_DB__USER=postgres
    export ADMIN_DB_PASSWORD=postgres
    export ADMIN_HOST="127.0.0.1"
    export ADMIN_DB_PORT=5435
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




