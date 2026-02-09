#!/bin/bash
# delete teh current pod so EKS will load its continer from the ECR
set -x
kubectl get pods
pod=`kubectl get pods | grep hopdevel-scimma-admin | grep Running | cut -f1 -d' '`
sleep 2
kubectl delete pod  $pod

