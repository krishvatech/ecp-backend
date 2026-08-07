from __future__ import annotations

import gzip
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SERVICE_FILE = REPO_ROOT / "deploy" / "ec2" / "ecp-startup.service"
USER_DATA_FILE = REPO_ROOT / "deploy" / "ec2" / "user-data.sh"
STARTUP_FILE = REPO_ROOT / "scripts" / "ecp-startup.sh"
WORKFLOW_FILE = REPO_ROOT / ".github" / "workflows" / "build-push-ecr.yml"


def test_startup_unit_does_not_remain_active_after_oneshot() -> None:
    unit = SERVICE_FILE.read_text()

    assert "Type=oneshot" in unit
    assert "RemainAfterExit=no" in unit
    assert "RemainAfterExit=yes" not in unit
    assert "KillMode=control-group" in unit
    assert "TimeoutStopSec=120" in unit


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


def test_workflow_performs_strict_post_refresh_verification() -> None:
    workflow = WORKFLOW_FILE.read_text()

    assert "bash -n rendered-ecp-user-data.sh" in workflow
    assert "install-ecp-startup-assets.sh <<'OUTER_SCRIPT'" in workflow
    assert '+ \"\\nOUTER_SCRIPT\",' in workflow
    assert "Rendered EC2 user-data still contains an unreplaced placeholder" in workflow
    assert "pid_belongs_to_backend_container" in workflow
    assert '[ "$HEALTH" = "healthy" ]' in workflow
    assert 'SERVICE_RESULT="success"' not in workflow  # must inspect runtime state
    assert "SERVICE_RESULT=$(sudo systemctl show" in workflow
    assert "Backend image, startup service, Docker health, local endpoint, and port ownership verification passed" in workflow
