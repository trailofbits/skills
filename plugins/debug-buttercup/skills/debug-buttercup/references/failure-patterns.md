# Buttercup Failure Patterns

## Table of Contents

1. [Redis AOF Cascade](#redis-aof-cascade)
2. [Disk Saturation from Corpus Writes](#disk-saturation-from-corpus-writes)
3. [DinD Failures](#dind-failures)
4. [OOM Kills](#oom-kills)
5. [Queue Backlog Stalls](#queue-backlog-stalls)
6. [Health Check Staleness](#health-check-staleness)
7. [Init Container Stuck on Redis](#init-container-stuck-on-redis)

---

## Redis AOF Cascade

**Symptoms**: Multiple pods restart within minutes of each other. Redis logs show:
```
Asynchronous AOF fsync is taking too long (disk is busy?)
```
Services crash with `redis.exceptions.ConnectionError: Connection refused` or `Connection reset by peer`.

**Root cause**: Disk I/O contention blocks Redis `fsync()`. Even tiny AOF writes stall when the underlying disk is busy with other workloads (DinD, fuzzer corpus, etc.). Liveness probe fails. Redis restarts. All services lose connection and cascade-restart.

**Diagnosis**:
```bash
# Check AOF delayed fsync count and config
kubectl exec -n crs <redis-pod> -- redis-cli INFO persistence | grep aof_delayed_fsync
kubectl exec -n crs <redis-pod> -- redis-cli CONFIG GET appendonly
# Check what /data is mounted on - disk vs tmpfs
kubectl exec -n crs <redis-pod> -- mount | grep /data
# Confirm cascade: check if multiple pods crashed with the same Redis error
kubectl logs -n crs <other-pod> --previous --tail=20
```

**Fixes**:
- Use memory-backed volume for Redis: `redis.master.persistence.medium: "Memory"` - AOF writes go to tmpfs, immune to disk contention
- Reduce disk I/O from other sources (corpus tmpfs, DinD storage)
- Note: `persistence.enabled` controls PVC creation, not AOF. AOF is set in Redis server config separately

---

## Disk Saturation from Corpus Writes

**Symptoms**: Pods slow down or hang. `df -h` shows root filesystem nearly full. Node shows `DiskPressure` condition.

**Diagnosis**:
```bash
kubectl describe node <node> | grep DiskPressure
kubectl exec -n crs <fuzzer-pod> -- du -sh /corpus/*
kubectl exec -n crs <fuzzer-pod> -- df -h
```

**Fixes**:
- Enable corpus tmpfs (moves corpus to `/dev/shm`)
- Reduce fuzzer-bot replicas
- Enable scratch-cleaner with shorter retention (`scratchRetentionSeconds`)
- Increase node disk size

---

## DinD Failures

**Symptoms**: Build-bot jobs fail with `Cannot connect to the Docker daemon`. DinD pod restarting or in CrashLoopBackOff.

**Diagnosis**:
```bash
kubectl logs -n crs -l app=dind --tail=100
kubectl describe pod -n crs <dind-pod>
kubectl exec -n crs <dind-pod> -- docker info
```

**Common causes**:
- Storage driver errors (overlay2 on incompatible filesystem)
- DinD running out of disk space (images accumulating)
- Resource limits too low (DinD needs significant CPU/memory for builds)

**Fixes**:
- Increase DinD resource limits (8000m CPU, 16Gi memory for large deployments)
- Prune images periodically: `docker system prune -af`
- Check storage driver compatibility

---

## OOM Kills

**Symptoms**: Pod status shows `OOMKilled`. Describe shows `Last State: Terminated, Reason: OOMKilled`.

**Diagnosis**:
```bash
kubectl describe pod -n crs <pod> | grep -A3 "Last State"
kubectl get events -n crs | grep OOM
kubectl top pods -n crs --sort-by=memory
```

**Common causes**:
- coverage-bot: needs 8Gi+ for large targets
- dind: building large projects

**Fixes**: Increase memory limits in values template for the affected service.

---

## Queue Backlog Stalls

**Symptoms**: Tasks not progressing. Scheduler logs show state stuck (e.g. never reaching `SUBMIT_BUNDLE`). Queue depths growing.

**Diagnosis**:
```bash
# Check all queue depths
for q in fuzzer_build_queue fuzzer_build_output_queue fuzzer_crash_queue \
         confirmed_vulnerabilities_queue orchestrator_download_tasks_queue \
         orchestrator_delete_task_queue tasks_ready_queue patches_queue \
         index_queue index_output_queue traced_vulnerabilities_queue \
         pov_reproducer_requests_queue pov_reproducer_responses_queue; do
  echo "$q: $(kubectl exec -n crs <redis-pod> -- redis-cli XLEN $q)"
done

# Check for stuck consumers
kubectl exec -n crs <redis-pod> -- redis-cli XINFO GROUPS fuzzer_build_queue
```

**Common causes**:
- Consumer pod crashed and didn't ack messages - messages stuck in PEL (pending entries list)
- Downstream service down (e.g. build-bot down -> build queue grows)
- Task timeout too short (`BUILD_TASK_TIMEOUT_MS` default 15min)

**Fixes**:
- Restart the stuck consumer pods
- Claim and ack orphaned pending messages
- Increase task timeouts if builds are legitimately slow

---

## Health Check Staleness

**Symptoms**: Pod keeps restarting despite logs showing it was working. Describe shows `Liveness probe failed`.

**Root cause**: The main process is alive but blocked (e.g. waiting on Redis, slow I/O), so it doesn't update `/tmp/health_check_alive`. After 600s stale + probe timing, Kubernetes kills it.

**Diagnosis**:
```bash
kubectl describe pod -n crs <pod> | grep -A5 "Liveness"
kubectl logs -n crs <pod> --previous --tail=50
```

**Fixes**:
- Fix the underlying block (Redis connection, disk I/O)
- Increase `livenessProbe.periodSeconds` or `failureThreshold`

---

## Init Container Stuck on Redis

**Symptoms**: Pod stuck in `Init:0/1`. Events show init container running but never completing.

**Root cause**: The `wait-for-redis` init container polls `redis-master:6379`. If Redis is down, all pods queue up waiting.

**Diagnosis**:
```bash
kubectl describe pod -n crs <pod> | grep -A10 "Init Containers"
kubectl get pods -n crs -l app.kubernetes.io/name=redis
```

**Fix**: Fix Redis first. Everything else will unblock automatically.
