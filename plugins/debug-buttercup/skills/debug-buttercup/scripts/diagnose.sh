#!/usr/bin/env bash
# Buttercup CRS diagnostic snapshot
# Collects pod status, events, resource usage, Redis health, and queue depths.
# Usage: bash diagnose.sh [--full]
#   --full: also dump recent logs from all pods (verbose)

set -euo pipefail

command -v kubectl >/dev/null 2>&1 || {
  echo "Error: kubectl not found"
  exit 1
}

NS="${BUTTERCUP_NAMESPACE:-crs}"
FULL=false
[[ "${1:-}" == "--full" ]] && FULL=true

section() { echo -e "\n===== $1 ====="; }

section "Pod Status"
kubectl get pods -n "$NS" -o wide

section "Pods with Restarts (termination reasons)"
for pod in $(kubectl get pods -n "$NS" -o jsonpath='{range .items[?(@.status.containerStatuses[0].restartCount > 0)]}{.metadata.name}{"\n"}{end}' 2>/dev/null); do
  restarts=$(kubectl get pod -n "$NS" "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null)
  reason=$(kubectl get pod -n "$NS" "$pod" -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}' 2>/dev/null)
  finished=$(kubectl get pod -n "$NS" "$pod" -o jsonpath='{.status.containerStatuses[0].lastState.terminated.finishedAt}' 2>/dev/null)
  printf "  %-55s restarts=%-3s reason=%-12s last=%s\n" "$pod" "$restarts" "${reason:--}" "${finished:--}"
done

section "Recent Warning Events"
kubectl get events -n "$NS" --field-selector type=Warning --sort-by='.lastTimestamp' 2>/dev/null | tail -30

section "Resource Usage (pods)"
kubectl top pods -n "$NS" 2>/dev/null || echo "(metrics-server not available)"

section "Resource Usage (nodes)"
kubectl top nodes 2>/dev/null || echo "(metrics-server not available)"

section "PVC Status"
kubectl get pvc -n "$NS" 2>/dev/null || echo "(no PVCs)"

# Find a redis pod
REDIS_POD=$(kubectl get pods -n "$NS" -l app.kubernetes.io/name=redis -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -n "$REDIS_POD" ]]; then
  section "Redis Health"
  kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli INFO memory 2>/dev/null | grep -E "used_memory_human|maxmemory_human" || true
  kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli INFO persistence 2>/dev/null | grep -E "aof_enabled|aof_last_bgrewrite_status|rdb_last_bgsave_status|aof_delayed_fsync" || true
  kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli INFO clients 2>/dev/null | grep -E "connected_clients|blocked_clients" || true
  kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli DBSIZE 2>/dev/null || true
  echo -n "  AOF config: "
  kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli CONFIG GET appendonly 2>/dev/null | tr '\n' ' ' || true
  echo
  echo -n "  /data mount: "
  kubectl exec -n "$NS" "$REDIS_POD" -- mount 2>/dev/null | grep /data || echo "(not found)"
  echo -n "  /data size: "
  kubectl exec -n "$NS" "$REDIS_POD" -- du -sh /data/ 2>/dev/null || echo "(not available)"

  section "Queue Depths"
  QUEUES=(
    fuzzer_build_queue
    fuzzer_build_output_queue
    fuzzer_crash_queue
    confirmed_vulnerabilities_queue
    orchestrator_download_tasks_queue
    tasks_ready_queue
    patches_queue
    index_queue
    index_output_queue
    traced_vulnerabilities_queue
    pov_reproducer_requests_queue
    pov_reproducer_responses_queue
    orchestrator_delete_task_queue
  )
  for q in "${QUEUES[@]}"; do
    len=$(kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli XLEN "$q" 2>/dev/null || echo "N/A")
    printf "  %-45s %s\n" "$q" "$len"
  done

  section "Task Registry"
  kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli HLEN tasks_registry 2>/dev/null || true
  echo -n "  cancelled: "
  kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli SCARD cancelled_tasks 2>/dev/null || echo "N/A"
  echo -n "  succeeded: "
  kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli SCARD succeeded_tasks 2>/dev/null || echo "N/A"
  echo -n "  errored:   "
  kubectl exec -n "$NS" "$REDIS_POD" -- redis-cli SCARD errored_tasks 2>/dev/null || echo "N/A"
else
  section "Redis"
  echo "WARNING: No redis pod found in namespace $NS"
fi

if $FULL; then
  section "Recent Logs (last 20 lines per pod)"
  for pod in $(kubectl get pods -n "$NS" -o jsonpath='{.items[*].metadata.name}'); do
    echo "--- $pod ---"
    kubectl logs -n "$NS" "$pod" --tail=20 2>/dev/null || echo "(no logs)"
    echo
  done
fi

echo -e "\n===== Diagnosis complete ====="
