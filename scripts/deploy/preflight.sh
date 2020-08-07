#!/bin/bash

# This file holds 'preflight' checks which are used to verify that everything is
# set up correctly for deploying.

RED='\033[0;31m'
GREEN='\033[0;32m'
NO_COLOR='\033[0m'

## Preflight checks: Logging code.
pf_check() {
    printf "preflight: checking for $1... " 1>&2
}

pf_fail() {
    printf "${RED}FAILED\nFATAL${NO_COLOR}: $1\n" 1>&2
    exit 1
}

pf_ok() {
    printf "${GREEN}OK${NO_COLOR}\n" 1>&2
}

## Actual preflight checks here.
check_for_aws() {
    pf_check "aws cli v2"
    command -v aws >/dev/null 2>&1 || {
        pf_fail "The AWS CLI v2 must be installed. For installation instructions, see:
https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html"
    }

    if aws --version | grep "aws-cli/2." > /dev/null; then
        pf_ok
    else
        pf_fail "The AWS CLI v2 must be installed. For installation instructions, see:
https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html"
    fi

    pf_check "access to ECR"
    if aws ecr describe-repositories --repository-names scimma-admin-web > /dev/null; then
        pf_ok
    else
        pf_fail "Unable to access ECR. Are your credentials set up correctly? Try running 'aws configure'."
    fi
}

check_for_docker() {
    pf_check "docker"
    if command -v docker > /dev/null; then
        pf_ok
    else
        pf_fail "Docker must be installed."
    fi
}

check_for_kubectl() {
    pf_check "kubectl"
    if command -v kubectl > /dev/null; then
        pf_ok
    else
        pf_fail "kubectl, the Kubernetes CLI, must be installed. See https://kubernetes.io/docs/tasks/tools/install-kubectl/."
    fi

    pf_check "kubectl configuration"
    if kubectl describe deployments hopdevel-scimma-admin >/dev/null; then
        pf_ok
    else
        pf_fail "kubectl is not configured to work with SCIMMA's EKS. Try running 'aws eks --region us-west-2 update-kubconfig --name hopDevelEksCluster'."
    fi
}

run_preflight_checks() {
    check_for_docker
    check_for_aws
    check_for_kubectl
}
