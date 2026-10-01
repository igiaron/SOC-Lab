# Configs

- `sysmonconfig.xml` — Sysmon config (SwiftOnSecurity base, extended to monitor LSASS
  ProcessAccess / Event 10, which is disabled by default). Apply with `Sysmon64.exe -c`.
- `inputs.conf` — Universal Forwarder input config for DC01 and WS01. Ships Security, System,
  Sysmon, and PowerShell channels to the `winlogs` index on the Splunk indexer (TCP 9997).

GPO settings:
command-line process auditing, PowerShell script block logging, Kerberos ticket auditing,
and scheduled-task (Other Object Access) auditing.
