# Procedure scripts

Put self-contained scripts directly in these folders:

- `Check-out`: runs during `Register-MobileDeployment`, after provisioning and before account verification/domain departure.
- `Check-in`: runs during `Unregister-Deployment`, before archive/account cleanup.

Windows hosts receive only `.ps1` files. Linux hosts receive only `.sh` files. Other files and subdirectories are ignored. Scripts run in filename order; names such as `10-configure.ps1` and `20-verify.ps1` make the order clear. Discovery snapshots the content once per procedure run, so every applicable host receives the same version even if the local files change during deployment. Script hashes identify the executed snapshots in the audit log. Linux CRLF line endings are normalized to LF before hashing/execution.

Hooks run on each target, not on the administrator machine. PowerShell uses a separate noninteractive process in the WinRM account context. Linux uses a separate Bash process via `dzdo`. Linux targets need `bash`, `base64`, `jq`, and the `timeout` utility. Each hook has a five-minute timeout. A PowerShell error or nonzero exit code, or a nonzero Bash exit code, fails that hook. All selected hooks are attempted; failure blocks check-out domain departure or check-in built-in cleanup on that host.

Each script receives these environment variables:

```text
MOBILE_NAME
MOBILE_PROCEDURE    # Check-in or Check-out
MOBILE_RUN_ID
```

The working directory is temporary. Supporting files and adjacent scripts are not copied. Hooks should be self-contained, handle repeated execution, and avoid interactive prompts. Use `throw`/`Write-Error` or `exit 1` in PowerShell, and a nonzero exit status in Bash, to report failure. Hooks are independent child processes, so shell variables and functions do not carry between scripts.

## Audit files

Each procedure creates a timestamped `.jsonl` file under the configured `MobileDeployments` directory (normally `.mobiles/.deployments`). The command prints the exact path at the end, including after an error. The log must be writable before deployment can proceed.

Every line is a JSON event with a UTC timestamp, run ID, mobile name, and procedure. Events record run start/completion, selected built-in tasks, target hosts, hook inventory (name/platform/SHA-256), host actions and failures, and procedure exceptions. Hook results include timestamps, exit code, and up to 64 KiB each of stdout and stderr. Script contents, credential payloads, and generated keytabs are not written to the journal. Hook output is logged, so scripts should not print passwords or other secrets. Protect the log directory using your normal administrator access controls.

Read a log in an editor or inspect it with PowerShell:

```powershell
$events = Get-Content 'path-to-run.jsonl' | ForEach-Object { $_ | ConvertFrom-Json }
$events | Where-Object Event -eq HostResult | ForEach-Object {
    $_.Data | Select-Object HostName, Platform, Success
    $_.Data.Actions | Format-Table Category, Name, Status
    $_.Data.Failures
}
```

Scheduled Windows post-deployment jobs are recorded as registered; their later execution is not represented as completed in this procedure log. Their existing endpoint result files remain separate. If a host disconnects before returning results, the journal records the transport/no-response failure, not an assertion that its actions completed. An interrupted administrator process can leave a start record without a completion record.
