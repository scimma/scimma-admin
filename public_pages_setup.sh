#!/bin/sh

system=devel

# Parse options
while getopts ":xvdpj" opt; do
  case $opt in 
    v)
      set -x
      ;;
    d)
	system=devel
	#export SCIMMA_ENVIRONMENT=devel
      ;;
    p)
	system=prod
	#export SCIMMA_ENVIRONMENT=prod
      ;;	
    h)
	-v verbose -p use prod databses -d use devel databases -j just run locally 
	;;
    x)
	set -x
	;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      ;;
  esac
done


#
#  Assume these have been done once
#  make localdev.conf
#  cp scimma_admin/sample_local_settings.py scimma_admin/local_settings.py


# Configuration
# export SSL_CERT_FILE=/Library/Frameworks/Python.framework/Versions/3.9/lib/python3.9/site-packages/certifi/cacert.pem
export SSL_CERT_FILE=/usr/local/etc/openssl/cert.pem



export REMOTE_TUNNEL="True"  #signal laptop development
export REMOTE_USER="don.petravick"
export SSH_KEY="~/.ssh/id_rsa"  # Path to your SSH key

export ARCHIVE_LOCAL_PORT=54320
export ARCHIVE_REMOTE_PORT=5432

export ADMIN_LOCAL_PORT=54321
export ADMIN_REMOTE_PORT=5432

export SCIMMA_ENVIRONMENT=dev

echo "$system"

get_secret () {
    aws secretsmanager get-secret-value --secret-id $1  | jq -r .SecretString
}



if [ "$system" = "prod" ]; then
    echo "System is production"
    
    export ARCHIVE_HOST="scotch.prod.hop.scimma.org"
    export ARCHIVE_DNS=hopprod-archive-ingest-db.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    export ARCHIVE_DB_INSTANCE_NAME=hopprod-archive-ingest-db
    export ARCHIVE_DB_SECRET_NAME=hopProd-archive-ingest-db-password
    export ARCHIVE_DB_PASSWD=`get_secret hopProd-archive-ingest-db-password`
    export ARCHIVE_DB_USERNAME=archive_db
    export ARCHIVE_DB_DBNAME=archivedb

    export ADMIN_HOST="scotch.prod.hop.scimma.org"
    export ADMIN_DNS=prod-scimma-admin-postgres.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    export ADMIN_DB_INSTANCE_NAME=prod-scimma-admin-postgres
    export ADMIN_DB_SECRET_NAME=prod-scimma-admin-db-password
    export ADMIN_DB_PASSWD=`get_secret prod-scimma-admin-db-password`
    export ADMIN_DB_USERNAME=scimma_admin
    export ADMIN_DB_DBNAME=prod_scimma_admin_db
    
else
    echo "System using devel system "
    export ARCHIVE_HOST="scotch.dev.hop.scimma.org"
    export ARCHIVE_DNS=hopdevel-archive-ingest-db.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    export ARCHIVE_DB_INSTANCE_NAME=hopdevel-archive-ingest-db
    export ARCHIVE_DB_SECRET_NAME=hopDevel-archive-ingest-db-password
    export ARCHIVE_DB_PASSWD=`get_secret hopDevel-archive-ingest-db-password`
    export ARCHIVE_DB_USERNAME=archive_db
    export ARCHIVE_DB_DBNAME=archivedb

    export ADMIN_HOST="scotch.dev.hop.scimma.org"
    export ADMIN_DNS=scimma-admin-postgres.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
    export ADMIN_DB_INSTANCE_NAME=scimma-admin-postgres
    export ADMIN_DB_SECRET_NAME=scimma-admin-db-password
    export ADMIN_DB_PASSWD=`get_secret scimma-admin-db-password`
    export ADMIN_DB_USERNAME=scimma_admin
    export ADMIN_DB_DBNAME=scimma_admin_db

fi


rm -f nohup.out
# Start Archive SSH tunnel in background
#echo "Starting ARCHIVE SSH tunnel..."
nohup ssh  -i $SSH_KEY -N -L $ARCHIVE_LOCAL_PORT:$ARCHIVE_DNS:5432 "$REMOTE_USER@$ARCHIVE_HOST" &  
ARCHIVE_TUNNEL_PID=$!
echo ARCHIVE_TUNNEL_PID

# Start ADMIN SSH tunnel in background
echo "Starting ADMIN SSH tunnel..."
nohup ssh  -i $SSH_KEY -N -L $ADMIN_LOCAL_PORT:$ADMIN_DNS:5432 "$REMOTE_USER@$ADMIN_HOST" &  
ADMIN_TUNNEL_PID=$!
echo ADMIN_TUNNEL_PID

sleep 2
echo take a peek at nohup.out
cat nohup.out  
sleep 4

# Cleanup function to kill the tunnel
cleanup() {
  echo "Shutting ARCHIVE down SSH tunnel..."
  kill $ARCHIVE_TUNNEL_PID 2>/dev/null
  wait $ARCHIVE_TUNNEL_PID 2>/dev/null
  echo "ARCHIVE Tunnel closed."

  echo "Shutting ADMIN down SSH tunnel..."
  kill $ADMIN_TUNNEL_PID 2>/dev/null
  wait $ADMIN_TUNNEL_PID 2>/dev/null
  echo "ADMIN Tunnel closed."
}

# Trap signals and errors to ensure cleanup
trap cleanup EXIT INT TERM ERR

# Wait briefly to ensure tunnels is up
sleep 2

#admin
#psql -h localhost -p 54321 -U scimma_admin -d scimma_admin_db -c '\dt' -e
#psql -h localhost -p 54320 -U scimma_admin -d scimma_admin_db -c '\dt' -e

# just do this so as to not think abou it.
(cd scimma_admin ; python manage.py makemigrations)
(cd scimma_admin ; python manage.py migrate)

#./scimma_admin/manage.py runserver === n.b. https not supported. 

#uwsgi --chdir=scimma_admin --module=scimma_admin.wsgi:application \
#      --env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
#      --pidfile=project-master.pid --http :8000 --processes 1 --threads 2 
echo uwsgi --version `uwsgi --version`
uwsgi --chdir=scimma_admin --show-config --module=scimma_admin.wsgi:application \
       --env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
      --pidfile=project-master.pid --http-socket 127.0.0.1:8010 --processes 1 --threads 2







