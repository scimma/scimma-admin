#!/bin/bash

Help() {
    echo "-p production, -d development -x  vebose -M don't migrate"  >&2
    exit 1
}
system=dev
migrate=true

# Parse options
while getopts "pdMhx" opt; do
  case $opt in
    p) system=prod ;;
    d) system=dev ;;
    M) migrate=false ;;
    h) Help ;;
    x) set -x ;;
    *) Help ;;
  esac
done
shift $((OPTIND -1))
if [ $# -gt 0 ]; then
    echo "Error: Unrecognized arguments: $@" >&2
    Help
fi

eval $(./config.sh $system)

#
#  Assume these have been done once
#  make localdev.conf
#  cp scimma_admin/sample_local_settings.py scimma_admin/local_settings.py
#  valid AWS credentials

# Configuration
export SSL_CERT_FILE=/usr/local/etc/openssl/cert.pem     # DLP's machine needs this
export REMOTE_TUNNEL="True"                              # signal laptop development
export REMOTE_USER="don.petravick"                       # user name bastion machine
export SSH_KEY="~/.ssh/id_rsa"  # Path to your SSH key   # 

rm -f nohup.out
# Start Archive SSH tunnel in background
#echo "Starting ARCHIVE SSH tunnel..."
connect=$ARCHIVE_TUNNEL_LOCAL_PORT:$ARCHIVE_TUNNEL_REMOTE_HOST:$ARCHIVE_TUNNEL_REMOTE_PORT
nohup ssh  -i $SSH_KEY -N -L $connect "$REMOTE_USER@$ARCHIVE_TUNNEL_BASTION" &  
ARCHIVE_TUNNEL_PID=$!

# Start ADMIN SSH tunnel in background
echo "Starting ADMIN SSH tunnel..."
connect=$ADMIN_TUNNEL_LOCAL_PORT:$ADMIN_TUNNEL_REMOTE_HOST:$ADMIN_TUNNEL_REMOTE_PORT
nohup ssh  -i $SSH_KEY -N -L $connect "$REMOTE_USER@$ADMIN_TUNNEL_BASTION" &  
ADMIN_TUNNEL_PID=$!

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

sleep 4
echo cat-ing nohup.out -- it should be emptysleep 4
cat nohup.out
Echo moving on from looking at nohup.com

# just do this so as to not think about it.
if [ $migrate = true  ] ; then
    echo migrating
    (cd scimma_admin ; python manage.py makemigrations)
    (cd scimma_admin ; python manage.py migrate)
fi 
#./scimma_admin/manage.py runserver === n.b. https not supported. 

#uwsgi --chdir=scimma_admin --module=scimma_admin.wsgi:application \
#      --env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
#      --pidfile=project-master.pid --http :8000 --processes 1 --threads 2 
echo uwsgi --version `uwsgi --version`
uwsgi --chdir=scimma_admin --show-config --module=scimma_admin.wsgi:application \
       --env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
      --pidfile=project-master.pid --http-socket 127.0.0.1:8000 --processes 1 --threads 2





