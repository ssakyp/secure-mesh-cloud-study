#!/usr/bin/env bash
# Azure (Student credit) cluster: 3-node AKS + a separate load-generator VM in the same region.
#   scripts/cluster_azure.sh preflight   # check SKU availability / quota FIRST (student subscriptions are restricted)
#   scripts/cluster_azure.sh up          # create everything (billing starts)
#   scripts/cluster_azure.sh down        # delete the resource group (billing stops)
# Image: built by CI to GHCR (public package) - no ACR cost.
set -euo pipefail
RG="${RG:-meshstudy-rg}"; LOC="${LOC:-westeurope}"; AKS="${AKS:-meshstudy}"
NODE_SIZE="${NODE_SIZE:-Standard_D2s_v5}"; NODES="${NODES:-3}"; VM_SIZE="${VM_SIZE:-Standard_D2s_v5}"
case "${1:-}" in
  preflight)
    az account show -o table
    az vm list-skus -l "$LOC" --size "${NODE_SIZE}" --resource-type virtualMachines --query "[].{name:name,restrictions:restrictions[].reasonCode}" -o table
    az vm list-usage -l "$LOC" -o table | grep -E "Total Regional vCPUs|DSv5|Name" || true
    echo "Need >= $((NODES*2+2)) free vCPUs. If the SKU is restricted try another region (LOC=...) or size (NODE_SIZE=Standard_D2as_v5 / Standard_B2s)." ;;
  up)
    az group create -n "$RG" -l "$LOC" -o none
    az aks create -g "$RG" -n "$AKS" --node-count "$NODES" --node-vm-size "$NODE_SIZE" --generate-ssh-keys --network-plugin azure -o none
    az aks get-credentials -g "$RG" -n "$AKS" --overwrite-existing
    az vm create -g "$RG" -n loadgen --image Ubuntu2204 --size "$VM_SIZE" --admin-username azureuser --generate-ssh-keys \
       --custom-data "$(dirname "$0")/loadgen-cloud-init.yaml" --public-ip-sku Standard -o table
    echo "next: scripts/install_istio.sh && IMAGE=ghcr.io/<you>/mesh-svc:<tag> scripts/deploy.sh"
    echo "then copy ~/.kube/config and this repo to the loadgen VM and run the matrix THERE (k6 must not share CPU with the cluster)." ;;
  down)
    az group delete -n "$RG" --yes --no-wait; echo "deletion started (check the portal to confirm nothing is left billing)" ;;
  *) echo "usage: $0 preflight|up|down"; exit 1 ;;
esac
