# SG alerts: maintenance on/off (SRE runbook)

Before maintenance that changes Security Groups, **turn alerts OFF first**, then make your changes. When you're done, **turn them back ON**.

## How to run a command

1. Sign in to the **AWS Console** with your own IAM user and MFA.
2. Click the **CloudShell** icon (`>_`) in the top bar.
3. Paste the command and press **Enter**.

---

### 🔴 Turn alerts OFF (start of maintenance)

```bash
read -rp "Reason for maintenance (optional, press Enter to skip): " R; aws ssm put-parameter --region eu-west-2 --name /secops/sg-monitor/notify-status --type String --overwrite --allowed-pattern '^(ON|OFF)$' --value OFF --description "${R:-no reason given}"
```

You'll be asked for a reason. Type something like `CHG-1234 DB patching`, or just press Enter to skip. The reason is shown in Teams if the switch has to be turned back ON automatically.

**Teams shows:** nothing.

---

### 🟢 Turn alerts ON (end of maintenance)

```bash
aws ssm put-parameter --region eu-west-2 --name /secops/sg-monitor/notify-status --type String --overwrite --allowed-pattern '^(ON|OFF)$' --value ON --description "Maintenance finished"
```

**Teams shows:** nothing.

---

## Good to know

- **The output looks like `{"Version": 7, "Tier": "Standard"}`.** That means it worked.
- **The switch is global.** OFF pauses alerts for **all** servers in **all** regions.
- **While alerts are OFF:**
  - SG changes are **not** alerted in real time.
  - The 10:00 daily scan is **skipped**.
- **Automatic reset at 07:00 and 19:00 IST.** If the switch is still OFF at either time, it is turned back ON and Teams shows 🔄 *SG monitoring switch turned back ON*, with your name, how long it was off and your reason. **If your maintenance runs past 07:00 or 19:00, turn alerts OFF again** right after that time.
- **Ports left open during maintenance are not lost.** Once alerts are ON again, the next 10:00 daily scan reports anything open to the internet.
- **`AccessDenied`** means you're not in the `sg-monitor-operators` group, or you signed in without MFA. Ask the platform admin.
- **Optional: check the current state:**
  ```bash
  aws ssm get-parameter --region eu-west-2 --name /secops/sg-monitor/notify-status --query Parameter.Value --output text
  ```
