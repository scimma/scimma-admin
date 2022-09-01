#!/bin/bash

set -eo pipefail

SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")"
source "${SCRIPT_DIR}/preflight.sh"
source "${SCRIPT_DIR}/docker.sh"

say_green() {
    local GREEN='\033[0;32m'
    local NO_COLOR='\033[0m'
    printf "${GREEN}$1${NO_COLOR}\n" 1>&2
}

cd $SCRIPT_DIR/../../

say_green "running preflight checks"
run_preflight_checks

say_green "rolling out new docker image"
kubectl rollout restart deployment/hopdevel-scimma-admin
