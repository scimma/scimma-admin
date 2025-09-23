#!/bin/sh

#
#  Assume these have been done once
#  make localdev.conf
#  cp scimma_admin/sample_local_settings.py scimma_admin/local_settings.py

#
#  TEar down any old postgres DB, and make a new one.
#
set -x
#!/bin/bash

# Configuration
#  ssh -i /Users/donaldpetravick/.ssh/id_rsa -l don.petravick scotch.dev.hop.scimma.org

export REMOTE_TUNNEL="True"  #signal laptop development
export REMOTE_USER="don.petravick"
export JUMP_HOST="scotch.dev.hop.scimma.org"
export REMOTE_HOST="scotch.dev.hop.scimma.org"
export SSH_KEY="~/.ssh/id_rsa"  # Path to your SSH key

export ARCHIVE_LOCAL_PORT=54320
export ARCHIVE_REMOTE_PORT=5432
export ARCHIVE_DNS=hopdevel-archive-ingest-db.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
export ARCHIVE_DB_INSTANCE=hopdevel-archive-ingest-db
export ARCHIVE_DB_SECRET_NAME=hopDevel-archive-ingest-db-password

export ADMIN_LOCAL_PORT=54321
export ADMIN_REMOTE_PORT=5432
export ADMIN_DNS=scimma-admin-postgres.cgaf3c8se1sj.us-west-2.rds.amazonaws.com
export ADMIN_DB_INSTANCE=scimma-admin-postgres
export ADMIN_DB_SECRET_NAME=scimma-admin-db-password

rm -f nohup.out
# Start Archive SSH tunnel in background
#echo "Starting ARCHIVE SSH tunnel..."
nohup ssh  -N -L $ARCHIVE_LOCAL_PORT:$ARCHIVE_DNS:5432 "$REMOTE_USER@$REMOTE_HOST" &  
ARCHIVE_TUNNEL_PID=$!
echo ARCHIVE_TUNNEL_PID

# Start ADMIN SSH tunnel in background
echo "Starting ADMIN SSH tunnel..."
nohup ssh  -N -L $ADMIN_LOCAL_PORT:$ADMIN_DNS:5432 "$REMOTE_USER@$REMOTE_HOST" &  
ADMIN_TUNNEL_PID=$!
echo ADMIN_TUNNEL_PID

sleep 2
echo take a peek at nohup.out
cat nohup.out  
sleep 10

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

python scimma_admin/mk_recent_model.py


# Run your program
# echo "Running program..."
uwsgi --chdir=scimma_admin --module=scimma_admin.wsgi:application \
      --env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
      --pidfile=project-master.pid --http :8000 --processes 1 --threads 2


