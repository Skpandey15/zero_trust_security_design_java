#!/usr/bin/env bash
# Bring the local k3d cluster back after a reboot, and wait until it is usable.
# Run from WSL:   deploy/scripts/cluster-up.sh
#
# Why this exists: after the machine restarts, `k3d cluster start` can leave a
# node stopped - an agent that races the control plane exits with "failed to
# start networking" and stays down. Volumes are pinned to nodes (local-path),
# so one missing agent takes the registry, Postgres and the build cache with it,
# and everything that depends on them then fails in confusing ways
# (ImagePullBackOff, CrashLoopBackOff). This starts what is down, in order,
# and does not return until the platform is healthy - or says exactly what is not.
#
# Safe to run any time; on a healthy cluster it only verifies. It touches only
# this cluster's own containers.
set -euo pipefail

CLUSTER="${K3D_CLUSTER:-dev}"
CONTEXT="k3d-${CLUSTER}"
NODE_TIMEOUT="${NODE_TIMEOUT:-180}"      # seconds to wait for all nodes Ready
WORKLOAD_TIMEOUT="${WORKLOAD_TIMEOUT:-420}"
KUBECTL="kubectl --context ${CONTEXT}"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
command -v k3d    >/dev/null || { echo "k3d not found" >&2; exit 1; }
docker info >/dev/null 2>&1   || { echo "the Docker daemon is not running" >&2; exit 1; }

node_containers() { docker ps -a --format '{{.Names}}' | grep -E "^k3d-${CLUSTER}-(server|agent)-" | sort; }
is_running()      { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]; }

# ---- 1. start the control plane and load balancer first ----------------------
if [ "${SKIP_K3D_START:-0}" = "1" ]; then
  log "SKIP_K3D_START=1 - not running 'k3d cluster start' (relying on the per-node retry below)"
else
  log "starting cluster '${CLUSTER}'"
  k3d cluster start "${CLUSTER}" --wait --timeout "${NODE_TIMEOUT}s" >/dev/null 2>&1 || true
fi

# ---- 2. make sure every node container is up; retry the ones that raced -------
# Servers first, then agents, so an agent never starts before the API it joins.
start_missing() {
  local started=0 c
  for c in $(node_containers | grep -- '-server-'; node_containers | grep -- '-agent-'); do
    if ! is_running "$c"; then
      log "  node container ${c} is stopped - starting it"
      docker start "$c" >/dev/null
      started=1
      sleep 5
    fi
  done
  return $started
}

log "waiting for the API server"
for _ in $(seq 1 60); do
  $KUBECTL get --raw /readyz >/dev/null 2>&1 && break
  sleep 3
done
$KUBECTL get --raw /readyz >/dev/null 2>&1 || { echo "the API server did not become ready" >&2; exit 1; }

log "waiting for all nodes to be Ready"
deadline=$(( $(date +%s) + NODE_TIMEOUT ))
while :; do
  start_missing || true
  not_ready=$($KUBECTL get nodes --no-headers 2>/dev/null | awk '$2 != "Ready" {print $1}')
  total=$($KUBECTL get nodes --no-headers 2>/dev/null | wc -l)
  expected=$(node_containers | grep -c -- '-\(server\|agent\)-')
  if [ -z "$not_ready" ] && [ "$total" -ge "$expected" ]; then break; fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "nodes not Ready after ${NODE_TIMEOUT}s: ${not_ready:-none registered yet}" >&2
    $KUBECTL get nodes >&2 || true
    exit 1
  fi
  sleep 5
done
$KUBECTL get nodes --no-headers | awk '{printf "  %-22s %s\n", $1, $2}'

# ---- 3. wait for the platform, in dependency order ---------------------------
# Only what exists is waited on, so this works on a cluster that has not had
# the platform installed yet.
wait_workload() {   # <namespace> <kind/name>
  local ns="$1" res="$2"
  $KUBECTL -n "$ns" get "$res" >/dev/null 2>&1 || return 0
  if $KUBECTL -n "$ns" rollout status "$res" --timeout="${WORKLOAD_TIMEOUT}s" >/dev/null 2>&1; then
    printf '  %-12s %-34s ready\n' "$ns" "$res"
  else
    printf '  %-12s %-34s NOT READY\n' "$ns" "$res"
    FAILED=1
  fi
}
FAILED=0

log "waiting for cluster services"
wait_workload kube-system deploy/coredns
wait_workload kube-system deploy/traefik
for d in cert-manager cert-manager-webhook cert-manager-cainjector; do wait_workload cert-manager "deploy/$d"; done

log "waiting for storage-backed services"
wait_workload registry deploy/registry
wait_workload zero-trust statefulset/postgres
wait_workload zero-trust deploy/redis
wait_workload jenkins statefulset/jenkins

log "waiting for the application"
for d in authorization-server resource-server bff frontend; do wait_workload zero-trust "deploy/$d"; done

# Pods that were mid-restart when the machine went down can be left in
# Unknown/Terminating; report them rather than hide them. Only this platform's
# namespaces decide pass/fail - another project sharing the cluster (tiny-url)
# is mentioned but never fails this script.
bad_pods() { $KUBECTL get pods -A --no-headers 2>/dev/null   | awk '$4 ~ /^(Unknown|Terminating|Error|ImagePullBackOff|CrashLoopBackOff)$/ {print $1"/"$2" ("$4")"}'; }
OURS='^(zero-trust|registry|jenkins|cert-manager|kube-system)/'
stuck=$(bad_pods | grep -E "$OURS" || true)
others=$(bad_pods | grep -vE "$OURS" || true)
if [ -n "$stuck" ]; then
  log "pods still not healthy:"; echo "$stuck" | sed 's/^/  /'
  FAILED=1
fi
if [ -n "$others" ]; then
  log "note - unhealthy pods outside this platform (not counted):"; echo "$others" | sed 's/^/  /'
fi

if [ "$FAILED" -ne 0 ]; then
  log "cluster is up but NOT fully healthy - see above"
  exit 1
fi
log "cluster '${CLUSTER}' is up and healthy"
