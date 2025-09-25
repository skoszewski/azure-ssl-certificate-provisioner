#!/usr/bin/env bash

set -eou pipefail

COMMAND="${1:-validate}"

case $COMMAND in
    init|-i)
        terraform init
        ;;

    validate|-v)
        terraform validate
        ;;
    
    format|-f)
        terraform fmt -recursive
        ;;

    plan|-p)
        if ! terraform fmt -check; then
            echo "Error: Terraform files are not properly formatted. Please run '$(basename $0) format' first."
            exit 1
        fi
        terraform validate
        if terraform plan -out=tfplan; then
            echo "Terraform plan saved to tfplan."
        else
            echo "Error: Terraform plan failed."
            exit 1
        fi
        ;;

    apply|-a)
        if [ ! -f tfplan ]; then
            echo "Error: tfplan file not found. Please run '$(basename $0) plan' first."
            exit 1
        fi
        if terraform apply tfplan; then
            rm -f tfplan
        else
            echo "Error: Terraform apply failed."
            exit 1
        fi
        ;;

    destroy|-d)
        shift
        terraform destroy "$@"
        ;;

    *)
        echo "Usage: $0 {validate|plan|apply|destroy}"
        exit 1
    ;;
esac
