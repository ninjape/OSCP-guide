# Kubernetes

## Kubectl commands

```
kubectl get nodes --all-namespaces -owide
kubectl get pods --all-namespaces -owide

### execute command on pods
kubectl get pods --all-namespaces -owide | grep default  | awk '{print $2}' | while read -r line; do echo $line; kubectl  exec $line -- env | grep -i pass; done

### execute command on one pod
kubectl exec mongo-exporter-845fb9c486-4hwtb -- mongo --version


### get env from pod
kubectl exec chi-click-replicated-0-0-0 -- env

### get shell on pod
kubectl exec --stdin --tty clickhouse-operator-6789b64dfb-84ljn -- /bin/bash

### get services
kubectl get services | grep Load

### apply pod
kubectl apply -f job-eks.yaml

kubectl describe job kube-bench
kubectl delete -f job-eks.yaml
kubectl logs kube-bench-xx6t7

### get deployments
kubectl get deployments -A -o yaml
```

```
kubescape scan framework nsa -v --output kubescape_results.txt
```

{% hint style="info" %}
[https://media.defense.gov/2021/Aug/03/2002820425/-1/-1/0/CTR\_Kubernetes\_Hardening\_Guidance\_1.1\_20220315.PDF\
https://hub.armosec.io/docs/controls](https://media.defense.gov/2021/Aug/03/2002820425/-1/-1/0/CTR\_Kubernetes\_Hardening\_Guidance\_1.1\_20220315.PDFhttps:/hub.armosec.io/docs/controls)
{% endhint %}

ExtensiveRoleCheck is a Python tool that scans the Kubernetes RBAC for risky roles. The tool is a part of the "Kubernetes Pentest Methdology" blog post series.

!!!!!Use the file from Tayfun &#x20;

{% file src="../.gitbook/assets/ExtensiveRoleCheck_modified (2).py" %}

{% embed url="https://github.com/cyberark/kubernetes-rbac-audit" %}

## Get env from pods

Use the below oneliner Get all env from all pods; you can replace "env" with any command and it will be run on the pod; instead of "db" you can use "pass" to grep for passwords&#x20;

```
kubectl get pods --all-namespaces -owide | grep default | awk '{print $2}' | while read -r line; do echo $line; kubectl exec $line -- env | grep -i db; done
```

This script that does same thing as above

```
./script.sh -c "<linux command>" 2>/dev/null

./script.sh -c "printenv" 2>/dev/null

./script.sh -c "printenv | grep -i pass*" 2>/dev/null
```

{% file src="../.gitbook/assets/script.sh" %}

{% hint style="info" %}
[https://github.com/cyberark/KubiScan](https://github.com/cyberark/KubiScan)
{% endhint %}

CIS kubernetes

For AWS EKS CIS use [kube-bench](https://github.com/aquasecurity/kube-bench)
