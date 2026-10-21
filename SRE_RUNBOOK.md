# SG alerts: maintenance on/off (SRE runbook)

Before maintenance that changes Security Groups, **turn alerts OFF**. When you're done, **turn them back ON**.
Teams announces both changes with your name, so everyone knows what's going on.

## How to run a command

1. Sign in to the **AWS Console** with your own IAM user and MFA.
2. Click the **CloudShell** icon (`>_`) in the top bar.
3. Paste the command and press **Enter**.

---

### 🔴 Turn alerts OFF (start of maintenance)

```bash
read -rp "Reason for maintenance (optional, press Enter to skip): " R; aws ssm put-parameter --region eu-west-2 --name /secops/sg-monitor/notify-status --type String --overwrite --allowed-pattern '^(ON|OFF)$' --value OFF --description "${R:-no reason given}"
```

You'll be asked for a reason. Type something like `CHG-1234 DB patching`, or just press Enter to skip.

**Teams shows:** ⏸️ *SG alerts PAUSED*, with your name, the time and the reason.

---

### 🟢 Turn alerts ON (end of maintenance)

```bash
aws ssm put-parameter --region eu-west-2 --name /secops/sg-monitor/notify-status --type String --overwrite --allowed-pattern '^(ON|OFF)$' --value ON --description "Maintenance finished"
```

**Teams shows:** ▶️ *SG alerts RESUMED*, with your name, how long the pause lasted, the SG changes made during it and a fresh scan of open ports.

---

## Good to know

- **The output looks like `{"Version": 7, "Tier": "Standard"}`.** That means it worked.
- **The switch is global.** OFF pauses real-time alerts for **all** servers in **all** regions.
- **While alerts are OFF:**
  - The 10:00 daily scan still runs.
  - A reminder is posted at 07:00 and 19:00 saying how long maintenance has been running.
- **Don't forget to turn alerts back ON.** Until you do, the reminders keep coming.
- **`AccessDenied`** means you're not in the `sg-monitor-operators` group, or you signed in without MFA. Ask the platform admin.
- **Optional: check the current state:**
  ```bash
  aws ssm get-parameter --region eu-west-2 --name /secops/sg-monitor/notify-status --query Parameter.Value --output text
  ```
