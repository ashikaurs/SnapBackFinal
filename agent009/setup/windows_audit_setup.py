
import argparse
import base64
import ctypes
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]

# Windows Advanced Audit Policy GUID for File System.
FILE_SYSTEM_AUDIT_GUID = (
    "{0CCE921D-69AE-11D9-BED3-505054503030}"
)


def is_admin():
    """Check whether the current process has administrator privileges."""

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def powershell_literal(value):
    """Safely represent a string as a PowerShell single-quoted value."""

    return "'" + str(value).replace("'", "''") + "'"


def run_command(command):
    """Run a command and raise a useful error if it fails."""

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip()
            or result.stdout.strip()
            or f"Command failed: {command[0]}"
        )

    return result.stdout


def apply_auditing_as_admin(folders):
    """Enable file-system auditing and install SACL rules."""

    # Enable successful File System auditing.
    run_command([
        "auditpol.exe",
        "/set",
        f"/subcategory:{FILE_SYSTEM_AUDIT_GUID}",
        "/success:enable"
    ])

    folders_json = json.dumps(folders)
    folders_b64 = base64.b64encode(
        folders_json.encode("utf-8")
    ).decode("ascii")

    # Install auditing rules only on SNAP_BACK protected folders.
    powershell_script = f"""
$ErrorActionPreference = 'Stop'

$foldersJson = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String('{folders_b64}')
)

$folders = @($foldersJson | ConvertFrom-Json)

$identity = [System.Security.Principal.SecurityIdentifier]::new(
    'S-1-1-0'
)

$rights = (
    [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
)

$inheritance = (
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
)

$propagation = [System.Security.AccessControl.PropagationFlags]::None
$auditFlags = [System.Security.AccessControl.AuditFlags]::Success

$rule = [System.Security.AccessControl.FileSystemAuditRule]::new(
    $identity,
    $rights,
    $inheritance,
    $propagation,
    $auditFlags
)

foreach ($folder in $folders) {{

    if (-not (Test-Path -LiteralPath $folder -PathType Container)) {{
        throw "Protected folder does not exist: $folder"
    }}

    $acl = Get-Acl -LiteralPath $folder -Audit

    $existingRules = $acl.GetAuditRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    )

    $ruleExists = $false

    foreach ($existing in $existingRules) {{

        if (
            $existing.IdentityReference.Value -eq $identity.Value -and
            [int]$existing.FileSystemRights -eq [int]$rights -and
            [int]$existing.AuditFlags -eq [int]$auditFlags -and
            [int]$existing.InheritanceFlags -eq [int]$inheritance -and
            [int]$existing.PropagationFlags -eq [int]$propagation
        ) {{
            $ruleExists = $true
            break
        }}
    }}

    if (-not $ruleExists) {{
        $acl.AddAuditRule($rule)
        Set-Acl -LiteralPath $folder -AclObject $acl
    }}

    # Verify that the rule is present.
    $verifiedAcl = Get-Acl -LiteralPath $folder -Audit

    $verifiedRules = $verifiedAcl.GetAuditRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    )

    $verified = $false

    foreach ($existing in $verifiedRules) {{

        if (
            $existing.IdentityReference.Value -eq $identity.Value -and
            [int]$existing.FileSystemRights -eq [int]$rights -and
            [int]$existing.AuditFlags -eq [int]$auditFlags -and
            [int]$existing.InheritanceFlags -eq [int]$inheritance -and
            [int]$existing.PropagationFlags -eq [int]$propagation
        ) {{
            $verified = $true
            break
        }}
    }}

    if (-not $verified) {{
        throw "Auditing rule verification failed: $folder"
    }}

    Write-Output "AUDIT_RULE_OK: $folder"
}}
"""

    encoded_script = base64.b64encode(
        powershell_script.encode("utf-16le")
    ).decode("ascii")

    output = run_command([
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded_script
    ])

    return output


def run_elevated_setup(folders):
    """Relaunch only the auditing setup with UAC elevation."""

    folders_json = json.dumps(folders)

    folders_b64 = base64.b64encode(
        folders_json.encode("utf-8")
    ).decode("ascii")

    python_exe = powershell_literal(sys.executable)
    project_root = powershell_literal(PROJECT_ROOT)

    powershell_script = f"""
$ErrorActionPreference = 'Stop'

$python = {python_exe}
$workingDirectory = {project_root}

$arguments = @(
    '-m',
    'setup.windows_audit_setup',
    '--apply-b64',
    '{folders_b64}'
)

$process = Start-Process `
    -FilePath $python `
    -ArgumentList $arguments `
    -WorkingDirectory $workingDirectory `
    -Verb RunAs `
    -Wait `
    -PassThru

exit $process.ExitCode
"""

    encoded_script = base64.b64encode(
        powershell_script.encode("utf-16le")
    ).decode("ascii")

    run_command([
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded_script
    ])


def ensure_windows_auditing(folders):
    """
    Configure Windows auditing for SNAP_BACK protected folders.

    Requests UAC elevation only when required.
    """

    valid_folders = []

    for folder in folders:

        path = Path(folder).resolve()

        if not path.exists() or not path.is_dir():
            raise ValueError(
                f"Invalid protected folder: {path}"
            )

        normalized = str(path)

        if normalized not in valid_folders:
            valid_folders.append(normalized)

    if not valid_folders:
        return

    print("\nConfiguring Windows File System Auditing...")

    if is_admin():
        output = apply_auditing_as_admin(valid_folders)
    else:
        print("Administrator permission is required.")
        print("Requesting permission through Windows UAC...")

        run_elevated_setup(valid_folders)
        output = "Auditing configured by elevated setup process."

    print(output)
    print("Windows auditing configured successfully.")


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--apply-b64",
        required=True
    )

    args = parser.parse_args()

    try:

        folders = json.loads(
            base64.b64decode(
                args.apply_b64
            ).decode("utf-8")
        )

        if not is_admin():
            raise PermissionError(
                "Elevated administrator privileges are required."
            )

        output = apply_auditing_as_admin(folders)

        print(output)
        return 0

    except Exception as error:

        print(f"Auditing setup failed: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
