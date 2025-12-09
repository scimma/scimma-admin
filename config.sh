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
# echo export SCIMMA_ENVIRONMENT=system  >&2

echo export PRINT_CONFIG=true
echo export DJANGO_DEBUG=false
echo export SECRET_KEY=zzzlocal
echo export SYMPA_CREDS="{}"


echo export SECURE_SSL_REDIRECT=false
echo export KAFKA_USER_AUTH_GROUP='"/Hopskotch Users"'
echo export KAFKA_BROKER_URL=dev.hop.scimma.org

echo export OIDC_RP_CLIENT_SECRET_SECRET_NAME="scimma-admin-keycloak-client-secret"
echo export OIDC_RP_CLIENT_ID="cilogon:/client_id/79be6fcf2057dbc381dfb8ba9c17d5fd"

echo export OIDC_OP_USER_ENDPOINT=http://localhost:8001



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






