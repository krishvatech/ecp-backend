# Marketing Hub background health alerting (B14)

**Status: review only. Nothing in this folder has been applied to any AWS account.**

The B10 health checks (`check_background_health`, Settings → Diagnostics) show
problems only when someone looks. This package adds alerts that do not depend
on the things they watch. In particular they do not depend on Celery Beat,
whose silent death is the main failure being detected.

| File | Purpose |
|---|---|
| `background-health-alerting.yaml` | CloudFormation: schedule, SSM document, IAM, alarms. An SNS topic ARN is a required parameter. |
| `simulate_alarms.py` | Development runner: runs the command in dry-run mode on a short period and prints the alarm transitions the template would produce. |
| `../../newsletter/management/commands/publish_background_health.py` | Runs the B10 checks once and publishes CloudWatch metrics. |

## How it works

```
EventBridge Scheduler (every minute, no retries)
  -> SSM Run Command, targets: tag aws:autoscaling:groupName = <backend ASG>
     -> on each instance: docker exec ecp-backend python manage.py publish_background_health
        -> same read-only probes as check_background_health (Redis ping, worker ping,
           Beat/task heartbeats in Redis, Mautic cron + messenger report)
        -> cloudwatch:PutMetricData (namespace ECP/MarketingHub, 20 values)
CloudWatch alarms (state change only) -> SNS topic (parameter) -> subscribers
```

* **Independent of Beat and the workers.** The schedule is AWS's, and the command runs in the web container. A stopped Beat or a dead worker cannot stop the monitor.
* **Read-only.** The command dispatches no task, writes no Beat evidence, sends no email and changes no Mautic state. It is tested for this (`test_health_alerting.py`).
* **Auto Scaling.** Instances are selected by the ASG tag, so new instances are covered and terminated ones drop out without any change. No metric carries an instance id. Each instance observes the same shared state (Redis, Beat evidence, Mautic), and alarms use `Maximum`, so N instances seeing one outage still give one alarm. If one instance's own ping fails (for example, a network problem on that host), `Maximum` still reports it.
* **Deduplication and recovery.** A CloudWatch alarm notifies only when its state changes (OK → ALARM, ALARM → OK). An outage that lasts hours sends one alarm and one recovery (`OKActions`), not one message per minute.
* **Missing samples.** If the scheduler, SSM, the container, the command or `PutMetricData` fails, `MonitorSample` stops arriving. `MonitorMissing` treats missing data as **breaching**, so a dead monitor alarms instead of looking healthy. The component alarms use `ignore`: they keep their current state while samples are missing. That means no false "recovered" message while the monitor is down, and no burst of OK messages when it comes back (`missing` would pass through INSUFFICIENT_DATA and fire every OK action on resume, which the local E2E showed).

### Command exit codes

| Code | Meaning | SSM run |
|---|---|---|
| 0 / 1 / 2 / 3 | Healthy / Warning / Unhealthy / Unknown. Metrics were published. | Success (the result is in the metrics) |
| 4 | No sample: collection crashed or `PutMetricData` failed | Failed |
| 124 | Timed out (`timeout 100`) | Failed |

### Metrics (namespace `ECP/MarketingHub`, dimension `Environment`)

| Metric | Extra dimension | Value |
|---|---|---|
| `MonitorSample` | none | 1 per completed observation (heartbeat) |
| `OverallStatusCode` | none | 0–3, the same as the exit code (for dashboards) |
| `ComponentUnhealthy` / `ComponentDegraded` / `ComponentUnknown` | `Component` | 0 or 1. Degraded means Warning *or* Unhealthy. A Disabled component reports 0. |

Components: `celery_beat`, `scheduled_tasks`, `celery_worker`, `redis_broker`, `mautic_cron`, `mautic_worker`.

### Alarms and thresholds (all are template parameters)

| Alarm | Condition | Default |
|---|---|---|
| `…-monitor-missing` | `MonitorSample` SampleCount < 1, missing = breaching | 10 of 10 min |
| `…-<component>-unhealthy` (6) | `ComponentUnhealthy` Max ≥ 1 | 3 of 3 min |
| `…-background-health-warning` | max of the six `ComponentDegraded` ≥ 1 (stays in ALARM while a warning escalates, so OK always means recovered) | 10 of 10 min |
| `…-background-health-unknown` | max of the six `ComponentUnknown` ≥ 1 | 15 of 15 min |

B10 already applies its own grace periods: Beat is stale after 3 missed periods plus the task time limit, and cron jobs use per-job intervals. The alarm periods add only enough time to ignore one-off blips.

## Prerequisites (verify before deploying)

1. The backend instances run the SSM agent and their role has `AmazonSSMManagedInstanceCore`. Check that each instance appears in **Systems Manager → Fleet Manager**.
2. The SSM agent's user (root) can run `docker exec ecp-backend …`.
3. The backend image includes `boto3` (it is already in `requirements.txt` for S3).
4. An SNS topic already exists, with confirmed subscribers, for operational alerts. Pass its ARN as `AlarmTopicArn`.
5. Optional backend settings (SSM `/ecp/<env>/`). All have safe defaults:
   * `HEALTH_ALERTING_ENVIRONMENT`: must equal the template's `Environment` parameter (default `development`, so **set it to `production`** in production).
   * `HEALTH_ALERTING_NAMESPACE` (default `ECP/MarketingHub`).
   * `HEALTH_ALERTING_AWS_REGION` (default: the instance's region).
   * Do **not** set `NEWSLETTER_BACKGROUND_HEALTH_ENABLED=false`, because Beat evidence would then read as Unknown.

## Deploy (staging first)

```bash
# 1. Prove the command inside a running container, without AWS:
docker exec ecp-backend python manage.py publish_background_health --dry-run
echo "exit=$?"     # 0-3 expected; read the JSON statuses

# 2. Review the change set (no resources are created until it is executed):
aws cloudformation create-change-set --change-set-type CREATE \
  --stack-name ecp-staging-background-health \
  --change-set-name initial --capabilities CAPABILITY_IAM \
  --template-body file://deploy/monitoring/background-health-alerting.yaml \
  --parameters ParameterKey=Environment,ParameterValue=staging \
               ParameterKey=BackendAutoScalingGroupName,ParameterValue=<asg> \
               ParameterKey=BackendInstanceRoleName,ParameterValue=<instance-role> \
               ParameterKey=AlarmTopicArn,ParameterValue=<sns-topic-arn>
aws cloudformation describe-change-set --stack-name ecp-staging-background-health --change-set-name initial

# 3. After executing it, confirm samples arrive (1-2 min):
aws cloudwatch get-metric-statistics --namespace ECP/MarketingHub --metric-name MonitorSample \
  --dimensions Name=Environment,Value=staging --statistics SampleCount \
  --start-time "$(date -u -d '-10 min' +%FT%TZ)" --end-time "$(date -u +%FT%TZ)" --period 60
```

IAM to review: the scheduler role may call `ssm:SendCommand` only with this stack's document, and only on instances tagged with the backend ASG name. The instance role gets only `cloudwatch:PutMetricData`, and only for this namespace. **Check in staging that the tag condition authorises tag-targeted `SendCommand`.** If it doesn't, the run history shows AccessDenied and `MonitorMissing` alarms.

## Runbook

| Alarm | First checks |
|---|---|
| monitor-missing | Scheduler → schedule invocation metrics; SSM → Run Command history (stdout shows `publish_background_health exit=N`). Exit 4: read stderr (`Could not publish …` means an IAM or region problem; `Could not observe …` means a database or settings problem). Exit 124: the database or Mautic is slow. Instance missing from Fleet Manager: SSM agent or role. |
| celery-beat-unhealthy | Is the Beat container running on the instance the deploy assigned? `docker logs --tail 100 <beat container>`. Scheduled tasks stop in the same minute, so expect `scheduled-tasks-unhealthy` too. |
| scheduled-tasks-unhealthy (alone) | Beat publishes but tasks don't run or fail. Check `ecp-celery-worker` logs and the queue length. |
| celery-worker-unhealthy | `docker ps` for `ecp-celery-worker` on each instance; worker logs; broker reachability. |
| redis-broker-unhealthy | ElastiCache health and security groups. Workers and Beat cannot work until it recovers. |
| mautic-cron-unhealthy | Mautic cron container; Settings → Diagnostics → Background shows which job is overdue or failing. |
| mautic-worker-unhealthy | The Mautic messenger consumer (only when transports are async). |
| warning / unknown | Not an outage yet. Open Settings → Diagnostics for the reason, and act if it persists. |

Recovery is automatic: when the component reports Healthy again for one period, the alarm returns to OK and SNS receives the recovery message.

## Rollback

* **Stop notifications only:** `aws cloudwatch disable-alarm-actions --alarm-names …` (re-enable with `enable-alarm-actions`).
* **Stop the monitor only:** set the schedule state to DISABLED. `MonitorMissing` will alarm unless its actions are disabled first.
* **Remove everything:** delete the stack. That removes the schedule, the SSM document, both IAM grants and the alarms. The SNS topic and its subscribers are not part of the stack and stay. The backend code needs no rollback: the command does nothing unless it is called.

## Troubleshooting

* `publish_error: NoRegionError`: set `HEALTH_ALERTING_AWS_REGION`, or the instance's default region.
* `publish_error: ClientError` with AccessDenied: the instance policy is missing, or the namespace setting differs from the `Namespace` parameter.
* Alarms stay INSUFFICIENT_DATA while samples arrive: `HEALTH_ALERTING_ENVIRONMENT` does not match the `Environment` parameter.
* Everything shows Unknown: the command could not read Beat evidence. Check that Redis is the same one the workers use, and the B10 notes.
* Local development: `python deploy/monitoring/simulate_alarms.py --period 5 --ticks 30 --command "python manage.py publish_background_health --dry-run"`. Stop Beat or the worker and watch the transitions.

## Estimated cost (verify against current AWS pricing)

20 custom metrics, about 43k `PutMetricData` calls a month per instance, 8 standard alarms and 2 metric-math alarms over 6 metrics each. That is a few US dollars a month.

---

## Mautic webhook delivery (B15 operational notes)

Settings → Diagnostics → Webhook now reads Mautic's own webhook list (`GET /api/hooks`, read-only). It shows:

* registration: Registered, Not Registered, Disabled in Mautic or Not Verifiable;
* whether the secret matches (yes/no; the secret is never shown);
* missing events;
* the delivery host, flagged when it is private;
* the last accepted, rejected and failed delivery seen by this receiver.

Facts verified against Mautic 7.1.3 that affect operations:

* **Queue mode.** In `immediate` mode Mautic posts during the triggering request and **never retries** a failed delivery. In `command_process` mode, events are queued, sent in batches by `mautic:webhooks:process` (cron), and retried on failure. ECP answers 500 when any event in a batch fails, and a retry is safe: tracking is unique per provider event, and consent writes are time-guarded upserts. `command_process` plus the cron is therefore the recommended production setting. Changing it is a Mautic configuration decision and has not been made here.
* **Auto-unpublish.** Mautic unpublishes a webhook after repeated failures, and immediately on HTTP 410. Diagnostics then shows "Disabled in Mautic". Republish it in Mautic once the receiver is fixed.
* **Mautic 7.1.3 bug.** When Mautic disables a webhook, its notifier can crash (`format() on null` in `WebhookKillNotificator`). That turns the triggering API request (for example a send) into a 500, although the send itself happened. Treat such a 500 as uncertain, as B11 does.
* **Private addresses.** Mautic refuses webhook URLs on private or loopback addresses unless they are listed in `webhook_allowed_private_addresses`. Production should deliver to the public HTTPS hostname.
* **Rate limiting.** The receiver is exempt from DRF's anonymous rate limit (`DRF_THROTTLE_ANON`, default `10/min`). Mautic posts from one address, one request per event in immediate mode, and does not retry a 429. The signature, body size (`MAUTIC_WEBHOOK_MAX_BODY_BYTES`, 1 MiB) and event count (`MAUTIC_WEBHOOK_MAX_EVENTS`, 500) checks bound each request instead.
