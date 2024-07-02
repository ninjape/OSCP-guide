#!/bin/bash



function usage {
    printf "Usage: $(basename $0) [-flag]" 2>&1
    printf '    -c  <command>'
    exit 1
}


if [[ ${#} -eq 0 ]]; then
    usage
fi


while getopts c: flag; do
    case "${flag}" in
        c) cmd=${OPTARG}
            ;;
        #*) echo "Invalid option: "$flag; usage; exit 1 ;;
    esac
done


for pod in $(kubectl get pods -A | awk 'NR>1{print $2}'); do
    namespace=`kubectl get pods -A | grep $pod |  cut -d " " -f1`
    cmd_result=`kubectl exec ${pod} --namespace $namespace -- ${cmd} 2>/dev/null`
    if [ -n "$cmd_result" ] ; then
        printf "###START###\n"
        echo $pod
        echo $namespace
        echo ${cmd_result} 2> /dev/null
        printf "###END###\n\n"
    fi
done