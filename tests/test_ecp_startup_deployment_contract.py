from __future__ import annotations

import gzip
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVICE_FILE = REPO_ROOT / "deploy" / "ec2" / "ecp-startup.service"
USER_DATA_FILE = REPO_ROOT / "deploy" / "ec2" / "user-data.sh"
STARTUP_FILE = REPO_ROOT / "scripts" / "ecp-startup.sh"
WORKFLOW_FILE = REPO_ROOT / ".github" / "workflows" / "build-push-ecr.yml"
SAFE_ROLLOUT_FILE = REPO_ROOT / ".github" / "scripts" / "ecp-safe-asg-rollout.sh"
RUNTIME_VERIFY_FILE = REPO_ROOT / ".github" / "scripts" / "ecp-verify-instance-runtime.sh"


def test_startup_unit_does_not_remain_active_after_oneshot() -> None:
    unit = SERVICE_FILE.read_text()

    assert "Type=oneshot" in unit
    assert "RemainAfterExit=no" in unit
    assert "RemainAfterExit=yes" not in unit
    assert "KillMode=control-group" in unit
    assert "TimeoutStopSec=120" in unit



def test_startup_unit_has_no_ssm_agent_dependency() -> None:
    unit = SERVICE_FILE.read_text()

    assert "After=network-online.target docker.service" in unit
    assert "Wants=network-online.target docker.service" in unit
    assert "amazon-ssm-agent.service" not in unit
    assert "snap.amazon-ssm-agent.amazon-ssm-agent.service" not in unit


def test_startup_never_runs_saleor_locally() -> None:
    startup = STARTUP_FILE.read_text()

    forbidden = (
        'SALEOR_DIR=',
        'START_SALEOR=',
        'docker-compose -f docker-compose.rds.yml',
        'http://127.0.0.1:8001/graphql/',
        'http://127.0.0.1:9000/',
        'Starting Saleor best-effort',
        'Running Saleor migrations',
    )

    for value in forbidden:
        assert value not in startup

    assert (
        "Saleor runs on separate infrastructure; "
        "no local Saleor runtime is started here"
    ) in startup


def test_user_data_stops_inherited_unit_before_replacing_and_restarts_it() -> None:
    user_data = USER_DATA_FILE.read_text()

    stop_index = user_data.index("systemctl stop ecp-startup.service")
    install_index = user_data.index(
        "install -m 0644 /tmp/ecp-startup.service "
        "/etc/systemd/system/ecp-startup.service"
    )
    restart_index = user_data.index("systemctl restart ecp-startup.service")

    assert stop_index < install_index < restart_index
    assert "systemctl start ecp-startup.service" not in user_data
    assert "SERVICE_RESULT=" in user_data
    assert "EXEC_STATUS=" in user_data


def test_rendered_user_data_is_valid_and_below_ec2_limit(tmp_path: Path) -> None:
    template = USER_DATA_FILE.read_text()
    rendered = (
        template.replace("__ECP_STARTUP_SH__", STARTUP_FILE.read_text().rstrip())
        .replace("__ECP_STARTUP_SERVICE__", SERVICE_FILE.read_text().rstrip())
    )

    assert "__ECP_STARTUP_SH__" not in rendered
    assert "__ECP_STARTUP_SERVICE__" not in rendered

    rendered_path = tmp_path / "rendered-ecp-user-data.sh"
    rendered_path.write_text(rendered)
    subprocess.run(["bash", "-n", str(rendered_path)], check=True)

    compressed = gzip.compress(rendered.encode(), compresslevel=9)
    assert len(compressed) <= 16_384


def test_startup_script_requires_container_cgroup_and_local_health() -> None:
    startup = STARTUP_FILE.read_text()

    assert "pid_belongs_to_backend_container" in startup
    assert "assert_backend_owns_port_8000" in startup
    assert 'if [ "$HEALTH" = "healthy" ]' in startup
    assert "http://127.0.0.1:8000/api/health/" in startup
    assert "authoritative check for this instance" in startup
    assert "remove_rogue_container_runtime" in startup
    assert 'systemctl kill --kill-who=all --signal=SIGKILL "$scope"' in startup
    assert '--signal=SIGKILL"$scope"' not in startup
    assert "cgroup.kill" in startup
    assert "ctr -n moby tasks rm -f" in startup
    assert "Killing orphaned containerd shim" in startup
    assert 'runtime_id="${scope#docker-}"' in startup
    assert "Same rogue runtime scope" in startup
    assert "port_8000_is_free_stably" in startup
    assert 'ctr -n moby containers rm "$task"' in startup
    assert 'ps -p "$rogue_pid" >/dev/null 2>&1 || return 0' not in startup


def test_workflow_performs_strict_post_refresh_verification() -> None:
    workflow = WORKFLOW_FILE.read_text()

    assert "bash -n rendered-ecp-user-data.sh" in workflow
    assert "Rendered EC2 user-data still contains an unreplaced placeholder" in workflow
    assert "pid_belongs_to_backend_container" in workflow
    assert '[ "$HEALTH" = "healthy" ]' in workflow
    assert 'SERVICE_RESULT="success"' not in workflow  # must inspect runtime state
    assert "SERVICE_RESULT=$(sudo systemctl show" in workflow
    assert "Backend image, startup service, Docker health, local endpoint, and port ownership verification passed" in workflow
    assert 'runtime_id="${scope#docker-}"' in workflow
    assert "Same rogue runtime scope" in workflow
    assert "port_8000_is_free_stably" in workflow
    assert 'sudo ctr -n moby containers rm "$task"' in workflow
    assert "legacy-disabled" in workflow

def test_safe_rollout_helpers_have_valid_shell_syntax() -> None:
    for path in (SAFE_ROLLOUT_FILE, RUNTIME_VERIFY_FILE):
        subprocess.run(["bash", "-n", str(path)], check=True)


def test_workflow_does_not_bypass_live_meeting_guard_on_rerun() -> None:
    workflow = WORKFLOW_FILE.read_text()

    assert "IS_RERUN=" not in workflow
    assert "forced_or_rerun" not in workflow
    assert "manual force deploy or rerun" not in workflow
    assert "force_deploy=true was explicitly selected" in workflow


def test_candidate_lt_is_not_activated_before_migrations_succeed() -> None:
    workflow = WORKFLOW_FILE.read_text()

    guard = workflow.index("Fail closed if another instance refresh is active")
    candidate = workflow.index("Create candidate launch template version without activating it")
    recheck = workflow.index("Recheck live-meeting capacity immediately before migration and rollout")
    migrate = workflow.index("Run Django backend migrations once")
    ssm = workflow.index("Update backend image URI in SSM")
    rollout = workflow.index("Safely roll ASG in two phases and hand off singleton Celery Beat")

    assert guard < candidate < recheck < migrate < ssm < rollout
    assert "Activate candidate launch template version" not in workflow

    candidate_block = workflow[candidate:recheck]
    assert "create-launch-template-version" in candidate_block
    assert "update-auto-scaling-group" not in candidate_block
    assert "Candidate is NOT active yet" in candidate_block
    assert "PREVIOUS_BACKEND_IMAGE_URI" in candidate_block


def test_workflow_uses_safe_two_phase_rollout_instead_of_unprotecting_everything() -> None:
    workflow = WORKFLOW_FILE.read_text()
    rollout = SAFE_ROLLOUT_FILE.read_text()

    assert "bash .github/scripts/ecp-safe-asg-rollout.sh" in workflow
    assert "Clearing scale-in protection from all current ASG instances" not in workflow
    assert "Clear ASG scale-in protection before instance refresh" not in workflow

    assert '"MinHealthyPercentage":100' in rollout
    assert '"MaxHealthyPercentage":200' in rollout
    assert '"AutoRollback":true' in rollout
    assert '--desired-configuration "$desired_configuration"' in rollout
    assert '"SkipMatching":true' in rollout
    assert '"ScaleInProtectedInstances":"Ignore"' in rollout
    assert 'MIN_SIZE" != "2"' in rollout
    assert 'DESIRED" != "2"' in rollout
    assert 'INSTANCE_COUNT" != "2"' in rollout
    assert "DesiredCapacity=" not in rollout
    assert "MinSize=" not in rollout
    assert "MaxSize=" not in rollout


def test_rollout_preserves_singleton_persistent_celery_beat() -> None:
    workflow = WORKFLOW_FILE.read_text()
    rollout = SAFE_ROLLOUT_FILE.read_text()

    assert "--scheduler django_celery_beat.schedulers:DatabaseScheduler" not in workflow
    assert "--scheduler django_celery_beat.schedulers:DatabaseScheduler" not in rollout

    assert "--pidfile=/tmp/celerybeat.pid" in rollout
    assert "--schedule=/tmp/celerybeat-schedule" in rollout
    assert "PersistentScheduler" in rollout
    assert "Preparing new Beat candidate without starting it" in rollout
    assert "Stopping old Beat but preserving its container for rollback" in rollout
    assert "Restoring old Beat before failing deployment" in rollout
    assert "restore_old_beat_best_effort" in rollout
    assert "could not send new Beat start command" in rollout
    assert "old Beat stop command did not complete cleanly" in rollout

    protect_candidate = rollout.index(
        "Protecting verified Beat candidate before stopping old Beat"
    )
    stop_old = rollout.index(
        "Stopping old Beat but preserving its container for rollback"
    )
    unprotect_old = rollout.index(
        "Making only the old Beat host eligible for phase 2 refresh"
    )

    assert protect_candidate < stop_old < unprotect_old


def test_rollout_only_completes_lifecycle_after_target_deregistration() -> None:
    rollout = SAFE_ROLLOUT_FILE.read_text()

    target_check = rollout.index('reason=$(echo "$json"')
    not_registered = rollout.index('Target.NotRegistered')
    completion = rollout.index("complete-lifecycle-action")

    assert target_check < not_registered < completion
    assert "Keeping lifecycle wait" in rollout


def test_rollout_scopes_lifecycle_completion_and_rolls_back_phase1_image_parameter() -> None:
    rollout = SAFE_ROLLOUT_FILE.read_text()

    assert 'local allowed_ids="$1"' in rollout
    assert "Leaving unrelated lifecycle wait untouched" in rollout
    assert "restore_previous_image_if_owned" in rollout
    assert "PREVIOUS_BACKEND_IMAGE_URI" in rollout
    assert "Phase 1 failed/rolled back" in rollout


def test_workflow_rechecks_capacity_immediately_before_mutation() -> None:
    workflow = WORKFLOW_FILE.read_text()

    assert "Recheck live-meeting capacity immediately before migration and rollout" in workflow
    assert "stable 2-instance baseline required for this rollout" in workflow
    assert "live/upcoming meeting capacity became active" in workflow


def test_runtime_verifier_checks_worker_process() -> None:
    verify = RUNTIME_VERIFY_FILE.read_text()
    assert "docker top ecp-celery-worker" in verify
    assert "[c]elery.*worker" in verify


def test_final_baseline_instances_are_protected_after_rollout() -> None:
    rollout = SAFE_ROLLOUT_FILE.read_text()
    assert "Protecting both validated baseline instances after rollout" in rollout
    assert "--instance-ids $ids" in rollout
    assert "--protected-from-scale-in" in rollout


def test_final_backend_verification_requires_healthy_container() -> None:
    workflow = WORKFLOW_FILE.read_text()

    final = workflow.index("Final backend container verification")
    final_block = workflow[final:]

    assert 'if [ \\"$HEALTH\\" = \\"healthy\\" ]' in final_block
    assert '[ \\"$HEALTH\\" = \\"none\\" ]' not in final_block

def test_workflow_does_not_mutate_current_instances_before_final_capacity_guard() -> None:
    workflow = WORKFLOW_FILE.read_text()

    assert "Install ECP startup assets on current ASG instances" not in workflow
    assert "Ensure Nginx static routes on current ASG instances" not in workflow
    assert "Ensure Nginx static routes after instance refresh" in workflow
    assert "Final live-meeting capacity recheck before ASG replacement" in workflow

    first_recheck = workflow.index(
        "Recheck live-meeting capacity immediately before migration and rollout"
    )
    migrate = workflow.index("Run Django backend migrations once")
    final_recheck = workflow.index(
        "Final live-meeting capacity recheck before ASG replacement"
    )
    ssm = workflow.index("Update backend image URI in SSM")
    rollout = workflow.index(
        "Safely roll ASG in two phases and hand off singleton Celery Beat"
    )

    assert first_recheck < migrate < final_recheck < ssm < rollout


def test_rollout_failure_cleanup_is_ownership_aware() -> None:
    rollout = SAFE_ROLLOUT_FILE.read_text()

    assert "trap failure_cleanup EXIT" in rollout
    assert "restore_previous_image_if_owned" in rollout
    assert 'pointer" = "$PREVIOUS_LT_VERSION"' in rollout
    assert "Re-protecting settled healthy baseline after failed rollout" in rollout
    assert "Not changing protection during unsettled failure state" in rollout


def test_runtime_verifier_reads_cache_without_writing() -> None:
    verify = RUNTIME_VERIFY_FILE.read_text()

    assert "CACHE / REDIS READ" in verify
    assert "cache.get('__ecp_runtime_verify_readonly__')" in verify
    assert "cache.set(" not in verify


def test_deployment_aws_cli_queries_do_not_use_jq_coalesce_operator():
    from pathlib import Path

    deployment_files = [
        Path(".github/workflows/build-push-ecr.yml"),
        Path(".github/scripts/ecp-safe-asg-rollout.sh"),
        Path(".github/scripts/ecp-verify-instance-runtime.sh"),
    ]

    bad_queries = []

    for path in deployment_files:
        for line_number, line in enumerate(
            path.read_text().splitlines(),
            start=1,
        ):
            if "--query" in line and " // " in line:
                bad_queries.append(
                    f"{path}:{line_number}: {line.strip()}"
                )

    assert not bad_queries, (
        "AWS CLI --query uses JMESPath, not jq; "
        "do not use the jq // operator:\n"
        + "\n".join(bad_queries)
    )


def test_singleton_beat_ssm_verifier_is_posix_shell_compatible():
    from pathlib import Path

    workflow = Path(
        ".github/workflows/build-push-ecr.yml"
    ).read_text()

    start = workflow.index(
        "- name: Verify singleton Celery Beat after safe rollout"
    )
    end = workflow.index(
        "- name: Verify deployed backend image on ASG instances",
        start,
    )

    step = workflow[start:end]

    # GitHub runner is explicitly Bash and should retain pipefail.
    assert "run: |\n          set -euo pipefail" in step

    # AWS-RunShellScript commands execute in a POSIX shell unless
    # Bash is explicitly invoked, so the direct payload must be portable.
    assert '"set -eu",' in step
    assert '"set -euo pipefail",' not in step
