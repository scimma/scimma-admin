#!/bin/bash
##
## This file is an overall configuration file for scimmma_admin development
## It's meant to be evaled in a overall driver shell script, e.g. ...
## eval "$(./config.sh local)"
##
## Suporting postigras datasnes (archivne and scimma daming)
## may be local or accessed via a tunnel. 
##
## CI (COnfuguration item 
## local  Configure for local scimma_admin databases.
## dev    Configure for tunnel access to AWS-resident development archive and admin databases. 
## prod   Configure for tunnel access to AWS-resident producti0on archive and admin databases. 


Help() {
    echo "config.sh <prod|dev|local>"  >&2
    exit 1
}

# require argments
if [ $# -eq 0 ]; then
    echo Arguements required >&2
    Help
fi

# Parse options
system=$1
if [[ "$system" == "prod" || "$system" == "dev" || "$system" == "local" ]]; then
    echo configuring for system $system   >&2
else
    Help
fi
# ensure all options are processed
shift
if [ $# -gt 0 ]; then
    echo "Error: Unrecognized arguments: $@" >&2
    Help
fi

# thie might be a shim for integration.
echo export SCIMMA_ENVIRONMENT=system  >&2

##
## Core DJANGO
##

### settings.py Name : DEBUG
### CI_Name          : DJANGO_DEBUG
### What is it       : true-> DEBUG  false -> INFO
### Why Config       : debug can be useful in development, DEBUG must not be used in prod.
### normal Default   : INFO
echo export DJANGO_DEBUG=false

### settings.py name : SECRET_KEY
### CI_Name(aws)     : SECRET_KEY_SECRET_NAME
### CI_Name(literal)): SECRET_KEY
### What is it       : A secret used internally by django to encrypt things.
### Why Config       : prod and dev deployment get the secret key  from AWS
### Why Config       : LOCAL_DEV just makes one up ("zzzlocal") as its' transient.
echo export SECRET_KEY=zzzlocal


##
## Sympa Related
##

###settings.py Name : SYMPA_CREDS
###CI_Name(aws)     : SYMPA_CREDS_SECRET_NAME
###CI_Name(literal) : SYMPA_CREDS
####What is it      : credentials to access SYMPA.
###What is it       : ALSO  flag indicating to not activate ...
###What is it       : sympa access IF SET TO {}
### Why Config      : to indicate whther to access SYMPA.
### WHy Config      : To authenticate to Symps 
#echo export SYMPA_CREDS_SECRET_NAME=scimma-admin-sympa-secret
echo export SYMPA_CREDS="{}"


##
## Auth related
##

### Settings.py name: SECURE_SSL_REDIRECT
### CI_Name          : SECURE_SSL_REDIRECT 
### What is it : causes django re redirect http to https automatically if true. 
### Why Config : Some development is simpler of done on http, to avoind the work of setting u  https stuff.
echo export SECURE_SSL_REDIRECT=false

### Settings.py name : :KAFKA_USER_AUTH_GROUP
### CI_Name          : KAFKA_USER_AUTH_GROUP
### What is it       : The name of the group in Keycloak that idenfies users authorized to use HOP. 
### Why Config       : dunno we have one keycloak and apparently one group shared between dev and prod
#Assert            : None
#echo export KAFKA_USER_AUTH_GROUP="/Hopskotch Users"
fixme

### Settings.py name : KAFKA_BROKER_URL
### CI_Name          : KAFKA_BROKER_URL
### What is it : The URL to a kafka Broker 
### Why Config : dev and prod use different instances (what about Localdev??)
### Override   : Value of env variable KAFKA_BROKER_URL 
### Assert     : is not None in Prod, dev.
echo export KAFKA_BROKER_URL=dog

### Settings.py name : OIDC_RP_CLIENT_ID
### CI_Name          : OIDC_RP_CLIENT_ID
### What is it : A client provided by the OIDC Provider
###terraform? : scimma_admin.tf: "scimma_admin_keycloak_client_id"
echo export OIDC_RP_CLIENT_ID="cilogon:/client_id/79be6fcf2057dbc381dfb8ba9c17d5fd"

### CI_Name(aws)      : OIDC_RP_CLIENT_SECRET_SECRET_NAME
### CI_Name(literal)  : OIDC_RP_CLIENT_SECRET
### What is it : A secret to access the OIDC provider, given a CLIENT_ID
### Why Config : TBD
### terraform? : scimma_admin.tf "scimma_admin_keycloak_client_secret"
### terraform? : scimma_admin.tf "cilogon_localdev_client_secret"
echo export OIDC_RP_CLIENT_SECRET_SECRET_NAME="scimma-admin-cilogon-localdev-client-secret"

### Settings.py name : OIDC_OP_USER_ENDPOINT
###  CI_NAME         : OIDC_OP_USER_ENDPOINT
### What is it       :
### Why config      :  we want production database for AWS scutt
### Why config      :  we eant to simulate this in local for developement flexablity.
echo export OIDC_OP_USER_ENDPOINT="https://login.scimma.org/realms/SCiMMA/protocol/openid-connect/userinfo"

# I want to make this work, but I want to complete integration loops even more
get_tunnel_info() {
    #Return the RDS json structure for DB instance passed in as $1
    echo "$1"  and  "$*" all 
    aws rds describe-db-instances --db-instance-identifier "$1"  \
	       --query 'DBInstances[0]' \
	       --output json
    }
	  
echo MARK "$system"  >&2
set -x


if [ "$system" = "prod" ]; then
    echo "environment configured for tunneling to prod databases" >&2
    # settings.oy CIs (recall these are also terraform CIs)
    echo export ARCHIVE_DB_INSTANCE_NAME=hopprod-archive-ingest-db
    echo export ARCHIVE_DB_PASSWORD_SECRET_NAME=hopProd-archive-ingest-db-password
    echo export ADMIN_DB_INSTANCE_NAME=prod-scimma-admin-postgres
    echo export ADMIN_DB_PASSWORD_SECRET_NAME=prod-scimma-admin-db-password

    echo export ARCHIVE_TUNNEL_BASTION="scotch.prod.hop.scimma.org"
    echo export ARCHIVE_TUNNEL_REMOTE_HOST=hopprod-archive-ingest-db.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    echo export ARCHIVE_TUNNEL_REMOTE_PORT=5432
    echo export ARCHIVE_TUNNEL_LOCAL_PORT=54361
    echo export ARCHIVE_TUNNEL_LOCAL_HOST=127.0.0.1
    echo export ADMIN_TUNNEL_BASTION="scotch.prod.hop.scimma.org"
    echo export ADMIN_TUNNEL_REMOTE_HOST=prod-scimma-admin-postgres.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    echo export ADMIN_TUNNEL_REMOTE_PORT=5432
    echo export ADMIN_TUNNEL_LOCAL_PORT=54360
    echo export ADMIN_TUNNEL_LOCAL_HOST=127.0.0.1
    
elif [ "$system" = "dev" ]; then
    echo "environment configured for tunneling to dev databases"  >&2
    # settings.oy CIs (recall these are also terraform CIs)
    echo export ARCHIVE_DB_INSTANCE_NAME=hopdevel-archive-ingest-db
    echo export ARCHIVE_DB_PASSWORD_SECRET_NAME=hopDevel-archive-ingest-db-password
    echo export ADMIN_DB_INSTANCE_NAME=scimma-admin-postgres
    echo export ADMIN_DB_PASSWORD_SECRET_NAME=scimma-admin-db-password

    #tunnel support CIs (Nothing to do with terraform) 
    echo export ARCHIVE_TUNNEL_BASTION="scotch.dev.hop.scimma.org"
    echo export ARCHIVE_TUNNEL_REMOTE_HOST=hopdevel-archive-ingest-db.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    echo export ARCHIVE_TUNNEL_REMOTE_PORT=5432
    echo export ARCHIVE_TUNNEL_LOCAL_PORT=54361
    echo export ARCHIVE_TUNNEL_LOCAL_HOST=127.0.0.1
    echo export ADMIN_TUNNEL_BASTION="scotch.dev.hop.scimma.org"
    echo export ADMIN_TUNNEL_REMOTE_HOST=scimma-admin-postgres.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    echo export ADMIN_TUNNEL_REMOTE_PORT=5432
    echo export ADMIN_TUNNEL_LOCAL_PORT=54360
    echo export ADMIN_TUNNEL_LOCAL_HOST=127.0.0.1
else

    echo "environment configured local postgres databases"  >&2
    echo export ARCHIVE_DB_NAME=postgres
    echo export ARCHIVE_DB_USER=postgres
    echo export ARCHIVE_DB_PASSWORD=postgres
    echo export ARCHIVE_DB_HOST="127.0.0.1"
    echo export ARCHIVE_DB_PORT=5433
    
    echo export ADMIN_DB_NAME=postgres
    echo export ADMIN_DB_USER=postgres
    echo export ADMIN_DB_PASSWORD=postgres
    echo export ADMIN_DB_HOST="127.0.0.1"
    echo export ADMIN_DB_PORT=5432

    #integreate me  belos 
    echo export SECURE_SSL_REDIRECT=false
    echo export OIDC_OP_USER_ENDPOINT='http://localhost:8001'
    echo export OIDC_RP_CLIENT_ID=dev-scimma-admin
fi






