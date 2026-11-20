# SENTINEL X local security agent

A small, cross-platform Python agent (Windows, macOS, Linux) that you install on devices **you own
or are authorized to monitor**. It enrolls with a one-time token, then periodically reports
approved, read-only telemetry and local detections to your SENTINEL X organization.

## What it does — and what it never does

| It does | It never does |
|---|---|
| Report CPU, memory and system-disk usage, uptime and process count | Execute commands, scripts or code sent by the server (there is no code path for it; a test scans the source to keep it that way) |
| Report network interface addresses and **listening TCP ports** | Read files, documents, browser data, keystrokes or screen contents |
| Detect: high CPU/memory/disk, and a **new listening port** (escalated for well-known backdoor ports such as 4444 or 31337) | Scan other machines or the network |
| Send lifecycle events (started, stopped) and heartbeats | Accept configuration outside a strict allow-list (heartbeat interval, enabled collectors, alert thresholds) |
| Queue events locally while the server is unreachable (bounded to 1000) | Talk plain HTTP to a remote server (HTTPS required; `localhost` is allowed for development) |

Collectors can be switched off per device from the console (**Devices → device → Agent configuration**).

## Requirements

* Python **3.10+** (`python --version`)
* Network access to your SENTINEL X API (HTTPS)
* No administrator rights are needed for normal operation

## Install

From the SENTINEL X repository folder:

```powershell
pip install ./agent
sentinel-agent --version
```

> Windows: if `sentinel-agent` is not found after installing, use `py -m sentinel_agent …` instead,
> or add the Python *Scripts* folder that pip prints to your `PATH`.

## Enroll

1. In the console open **Devices → Enroll device**, give the token a label and create it.
2. Copy the enrollment command shown (the token is displayed only once):

```powershell
sentinel-agent enroll --server https://your-console.example.com --token sxe.xxxxx
```

`--server` is the console/API origin. In local development use `http://localhost:5173` (the
Vite dev server) or `http://127.0.0.1:8000` (the API directly). Add `--name "Reception PC"` to set a
display name. On success the device credential is saved to the agent data folder (below).

## Run

```powershell
sentinel-agent run          # runs until Ctrl+C; sends heartbeats every 60 s by default
sentinel-agent run --once   # a single cycle (useful for testing)
sentinel-agent status       # enrollment, last heartbeat, queued events, active configuration
```

### Run in the background

**Windows (Task Scheduler, starts at log-on, no admin needed)** — in PowerShell:

```powershell
$exe = (Get-Command sentinel-agent).Source
$action = New-ScheduledTaskAction -Execute $exe -Argument "run"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit 0
Register-ScheduledTask -TaskName "SENTINEL X Agent" -Action $action -Trigger $trigger -Settings $settings
Start-ScheduledTask -TaskName "SENTINEL X Agent"
```

**Linux (systemd user service)** — the unit expects `pip install --user ./agent`
(`~/.local/bin/sentinel-agent`); edit `ExecStart` if you installed into a virtualenv:

```bash
mkdir -p ~/.config/systemd/user
cp agent/service/sentinel-agent.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now sentinel-agent
journalctl --user -u sentinel-agent -f
```

**macOS**: run `sentinel-agent run` from a terminal, or create a LaunchAgent that runs it at log-in.

## Files

| Platform | Data folder |
|---|---|
| Windows | `%LOCALAPPDATA%\SentinelX\agent` |
| macOS | `~/Library/Application Support/SentinelX/agent` |
| Linux | `~/.config/sentinel-x-agent` (or `$XDG_CONFIG_HOME`) |

Override with the `SENTINEL_AGENT_HOME` environment variable. The folder contains `state.json`
(device credential, created with owner-only permissions on macOS/Linux), `spool.jsonl` (events
waiting to be delivered) and `logs/agent.log` (rotated at 1 MB, 3 files kept).

## Credential management

* `sentinel-agent rotate-credentials` replaces the device credential; the old one stops working.
* If an administrator **revokes** the device in the console, the agent stops on its next contact
  (exit code 3) and logs that it must be re-enrolled.

## Remove (uninstall)

1. Unregister the device and delete its credential (also tells the server it was removed):

   ```powershell
   sentinel-agent unenroll --purge
   ```

   If the server is unreachable, revoke the device in the console instead (**Devices → device → Revoke device**).
2. Remove the background task, if you created one:

   ```powershell
   Unregister-ScheduledTask -TaskName "SENTINEL X Agent" -Confirm:$false
   ```

   ```bash
   systemctl --user disable --now sentinel-agent && rm ~/.config/systemd/user/sentinel-agent.service
   ```
3. Uninstall the package:

   ```powershell
   pip uninstall sentinel-x-agent
   ```

## Protocol (for integrators)

All requests are `POST` JSON to `<server>/api/v1/agent/…`; after enrollment they carry
`Authorization: Bearer sxd.<org>.<device>.<secret>`.

| Endpoint | Purpose |
|---|---|
| `/enroll` | exchange an enrollment token + device facts for a device credential and initial config |
| `/heartbeat` | report telemetry; the response carries the current allow-listed config and its version |
| `/events` | submit up to 100 events (`event_type`, `category`, `severity`, `title`, optional `dedup_key`, `raw` ≤ 16 KB) |
| `/credentials/rotate` | replace the device credential |
| `/unenroll` | revoke this device |

## Tests

```powershell
pip install "./agent[test]"
cd agent
python -m pytest
```
