#!/bin/bash
# a conveience to look a the logs after a a deployment 
kubectl get pods
pod=`kubectl get pods | grep hopdevel-scimma-admin | grep Running | cut -f1 -d' '`
sleep 2
kubectl logs -f $pod
#sleep 10 
##curl https://admin.dev.hop.scimma.org/public_topics
