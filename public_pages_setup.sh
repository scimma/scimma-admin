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
REMOTE_USER="don.petravick"
ARCHIVE_HOST="scotch.dev.hop.scimma.org"
ADMIN_HOST="scotch.dev.hop.scimma.org"
SSH_KEY="~/.ssh/id_rsa"  # Path to your SSH key

ARCHIVE_LOCAL_PORT=54320
ARCHIVE_REMOTE_PORT=5432

ADMIN_LOCAL_PORT=54320
ADMIN_REMOTE_PORT=5432


# Start Archive SSH tunnel in background
echo "Starting ARCHIVE SSH tunnel..."
ssh -i "$SSH_KEY" -N -L "$ARCHIVE_LOCAL_PORT:127.0.0.1:$ARCHIVE_REMOTE_PORT" "$REMOTE_USER@$ARCHIVE_HOST" &
ARCHIVE_TUNNEL_PID=$!

# Start ADMIN SSH tunnel in background
echo "Starting ADMIN SSH tunnel..."
ssh -i "$SSH_KEY" -N -L "$ADMIN_LOCAL_PORT:127.0.0.1:$ADMIN_REMOTE_PORT" "$REMOTE_USER@$ADMIN_HOST" &
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

# Wait briefly to ensure tunnels is up
sleep 2

# Run your program
# echo "Running program..."
uwsgi --chdir=scimma_admin --module=scimma_admin.wsgi:application \
      --env DJANGO_SETTINGS_MODULE=scimma_admin.settings --master \
      --pidfile=project-master.pid --http :8000 --processes 1 --threads 2


