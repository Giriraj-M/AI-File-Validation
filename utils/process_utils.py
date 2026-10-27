import os
import shutil
import subprocess
import logging
from config import Config

logger = logging.getLogger("FileGuard.ProcessUtils")

def run_external_command(cmd_args: list[str], timeout: int | None = None) -> tuple[bool, str, str]:
    """
    Safely executes an external command with timeout and argument isolation.
    Returns: (success: bool, stdout: str, stderr: str)
    """
    if not cmd_args or not cmd_args[0]:
        return False, "", "Empty command provided."

    # Validate that executable exists
    exe_path = shutil.which(cmd_args[0])
    if not exe_path and not os.path.exists(cmd_args[0]):
        return False, "", f"Executable '{cmd_args[0]}' not found on system."

    timeout_sec = timeout or getattr(Config, "RECOVERY_TIMEOUT_SECONDS", 120)

    try:
        proc = subprocess.run(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
            shell=False  # Security: avoid shell injection
        )
        success = (proc.returncode == 0)
        return success, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        logger.warning(f"Process timed out after {timeout_sec}s: {' '.join(cmd_args)}")
        return False, "", f"Execution timed out after {timeout_sec} seconds."
    except Exception as e:
        logger.error(f"Process execution error: {e}", exc_info=True)
        return False, "", str(e)
