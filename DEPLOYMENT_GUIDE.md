# SG Monitor: deployment guide

This guide sets up alerts in Microsoft Teams whenever a Security Group opens a sensitive port to the internet. The whole flow runs on AWS managed services: there are no agents on the servers and only one Lambda function. Every step is a copy-paste command for **AWS CloudShell**. Expect it to take about 45 minutes.

## What you are building

```
 Server regions (other than London)               London (eu-west-2): home region
 ┌──────────────────────────────┐               ┌───────────────────────────────────────────────┐
 │ CloudTrail → EventBridge rule │──forward──►  │ default event bus                              │
 │ "sg-monitor-forward-to-home"  │               │   rule sg-monitor-sg-events ───────┐           │
 └──────────────────────────────┘               │   rule sg-monitor-switch-change ───┤           │
                                                 │ Scheduler 10:00 IST daily_scan ────┤           │
                                                 │ Scheduler 07:00 + 19:00 IST report ┤           │
                                                 │                                    ▼           │
                                                 │            Lambda "sg-monitor" (read-only)     │
                                                 │   reads switch: SSM /secops/sg-monitor/notify-status
                                                 │            │                     │ on failure  │
                                                 │            ▼                     ▼             │
                                                 │   Teams Workflow webhook   SQS sg-monitor-dlq  │
                                                 │                            + CloudWatch alarms → SNS email
                                                 └───────────────────────────────────────────────┘
```

| Flow | Trigger | Behaviour |
|---|---|---|
| Daily scan | 10:00 IST | Scans every SG in the 3 server regions. **Always runs**, whether alerts are paused or not. Posts findings, or "✅ nothing open" as a daily sign that monitoring is working. |
| Real-time check | SG / ENI / instance / public IP change | When the switch is **ON**: alerts if a critical port became reachable from the internet, naming the IAM user who did it. When **OFF**: the event is logged as `SKIPPED (maintenance)` and no alert is sent. |
| Switch report | 07:00 and 19:00 IST | ON: "✅ monitoring active". OFF: "⚠️ Maintenance is going on from the past Xh Ym. Please be aware." |
| Switch change | An SRE runs the ON or OFF command | OFF: "⏸️ paused by X". ON: "▶️ resumed by X", plus the SG changes made during the pause and a full catch-up scan. |

**Fail-safe:** if the switch is missing, unreadable or holds any value other than `OFF`, the Lambda behaves as if it were **ON** and flags the problem in Teams.

---

## Step 0: Get ready (5 min)

1. **Sign in** to the AWS Console as an admin user **with MFA**, and switch the region to **Europe (London) eu-west-2**.
2. **Upload the project.** On your machine, zip the project and leave the tests out:
   ```bash
   cd ~ && zip -r sg-monitor.zip sg-monitor -x 'sg-monitor/tests/*' '*/__pycache__/*'
   ```
3. **Open CloudShell** (the `>_` icon in the console's top bar). Choose **Actions → Upload file → sg-monitor.zip**, then run:
   ```bash
   unzip -o sg-monitor.zip && cd ~/sg-monitor
   ```
4. **Set the variables.** Edit the four `EDIT` lines in `config/vars.sh` (`nano config/vars.sh`), then run:
   ```bash
   source config/vars.sh
   ```
   **If CloudShell times out**, run `cd ~/sg-monitor && source config/vars.sh` again before continuing.
5. **Fill in your account details.** This writes your account ID, region and email into every template:
   ```bash
   sed -i "s/<ACCOUNT_ID>/$ACCOUNT_ID/g; s/<HOME_REGION>/$HOME_REGION/g; s/<ALERT_EMAIL>/$ALERT_EMAIL/g" \
     iam/*.json eventbridge/*.json scheduler/*.json cloudtrail/*.json budget/*.json
   grep -rl '<ACCOUNT_ID>\|<HOME_REGION>\|<ALERT_EMAIL>' . || echo "All placeholders filled"
   ```

---

## Step 1: Check for a CloudTrail trail (5 min)

EventBridge receives the "AWS API Call via CloudTrail" events from an active trail, and the trail is also your audit record.

1. **Check for an existing multi-region trail that is logging:**
   ```bash
   aws cloudtrail describe-trails --region $HOME_REGION \
     --query 'trailList[?IsMultiRegionTrail].[Name,HomeRegion,S3BucketName]' --output table
   ```
   If a trail is listed, confirm it is logging:
   ```bash
   aws cloudtrail get-trail-status --name <TRAIL_NAME> --region <ITS_HOME_REGION> --query IsLogging
   ```
   If it returns `true`, skip to Step 2.

2. **Only if no trail exists, create one** (management events only, which keeps the cost at roughly $0.20–0.40 a month):
   ```bash
   BUCKET="sg-monitor-cloudtrail-$ACCOUNT_ID"
   aws s3api create-bucket --bucket $BUCKET --region $HOME_REGION \
     --create-bucket-configuration LocationConstraint=$HOME_REGION
   aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration \
     BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   aws s3api put-bucket-policy --bucket $BUCKET --policy file://cloudtrail/bucket-policy.json
   aws s3api put-bucket-lifecycle-configuration --bucket $BUCKET --lifecycle-configuration file://cloudtrail/lifecycle.json
   aws s3api put-bucket-tagging --bucket $BUCKET --tagging 'TagSet=[{Key=Project,Value=sg-monitor}]'

   aws cloudtrail create-trail --name sg-monitor-trail --s3-bucket-name $BUCKET \
     --is-multi-region-trail --enable-log-file-validation --region $HOME_REGION \
     --tags-list Key=Project,Value=sg-monitor
   aws cloudtrail start-logging --name sg-monitor-trail --region $HOME_REGION
   ```
   > ⚠️ **Do not enable data events, Insights or CloudTrail Lake.** They are the only settings that would push this flow over the $2/month budget.

---

## Step 2: Create the Teams webhook (5 min, in Microsoft Teams)

1. **Choose the channel.** Pick the **private** SRE channel that should receive alerts.
2. **Add the workflow.** On the channel, open **⋯ → Workflows** and pick the template **"Send webhook alerts to a channel"**. (Some tenants call it "Post to a channel when a webhook request is received".)
3. **Finish the setup.** Name it `SG Monitor`, confirm the team and channel, and click **Add workflow**.
4. **Copy the URL** it shows. You need it in Step 7.

**Treat this URL as a password.** Anyone who has it can post into the channel.

**Ownership:** the workflow belongs to whoever created it. Create it from a **shared or service account**, or add co-owners, so alerts don't stop when that person leaves.

---

## Step 3: Create the ON/OFF switch (1 min)

```bash
aws ssm put-parameter --region $HOME_REGION \
  --name /secops/sg-monitor/notify-status \
  --type String --tier Standard --value ON \
  --allowed-pattern '^(ON|OFF)$' \
  --description "Initial setup" \
  --tags Key=Project,Value=sg-monitor
```

---

## Step 4: Give SREs access to the switch (3 min)

```bash
aws iam create-group --group-name sg-monitor-operators
aws iam put-group-policy --group-name sg-monitor-operators \
  --policy-name sg-monitor-switch --policy-document file://iam/sre-switch-operators-policy.json
aws iam attach-group-policy --group-name sg-monitor-operators \
  --policy-arn arn:aws:iam::aws:policy/AWSCloudShellFullAccess
for u in $SRE_USERS; do aws iam add-user-to-group --group-name sg-monitor-operators --user-name "$u"; done
```

**Optional but recommended: require MFA to flip the switch.**

1. Add the MFA policy:
   ```bash
   aws iam put-group-policy --group-name sg-monitor-operators \
     --policy-name sg-monitor-require-mfa --policy-document file://iam/sre-require-mfa-policy.json
   ```
2. Test it. An SRE who **signed in to the console with MFA** opens CloudShell and runs the OFF and ON commands from `SRE_RUNBOOK.md`.
   - If both work, keep the policy.
   - If they get `AccessDenied` even though they signed in with MFA, remove the policy and rely on requiring MFA for console sign-in instead:
     ```bash
     aws iam delete-group-policy --group-name sg-monitor-operators --policy-name sg-monitor-require-mfa
     ```

---

## Step 5: Set up failure handling (3 min)

**Dead-letter queue and email topic:**
```bash
aws sqs create-queue --queue-name sg-monitor-dlq --region $HOME_REGION \
  --attributes MessageRetentionPeriod=1209600,SqsManagedSseEnabled=true \
  --tags Project=sg-monitor
python3 -c 'import json; print(json.dumps({"Policy": open("iam/dlq-queue-policy.json").read()}))' > /tmp/dlq-attrs.json
aws sqs set-queue-attributes --queue-url $DLQ_URL --attributes file:///tmp/dlq-attrs.json --region $HOME_REGION

aws sns create-topic --name sg-monitor-ops --region $HOME_REGION --tags Key=Project,Value=sg-monitor
aws sns subscribe --topic-arn $SNS_ARN --protocol email --notification-endpoint $ALERT_EMAIL --region $HOME_REGION
```
📧 **Open the confirmation email and click "Confirm subscription"**, otherwise no alarm emails will arrive.

---

## Step 6: Create the IAM roles (3 min)

```bash
# Lambda: read-only inventory, read the switch, read CloudTrail history, logs, DLQ
aws iam create-role --role-name sg-monitor-lambda-role \
  --assume-role-policy-document file://iam/lambda-trust.json --tags Key=Project,Value=sg-monitor
aws iam put-role-policy --role-name sg-monitor-lambda-role \
  --policy-name sg-monitor-lambda --policy-document file://iam/lambda-policy.json

# Scheduler: may only invoke this function
aws iam create-role --role-name sg-monitor-scheduler-role \
  --assume-role-policy-document file://iam/scheduler-trust.json --tags Key=Project,Value=sg-monitor
aws iam put-role-policy --role-name sg-monitor-scheduler-role \
  --policy-name sg-monitor-scheduler --policy-document file://iam/scheduler-policy.json

# EventBridge forwarder: may only put events on the London default bus
aws iam create-role --role-name sg-monitor-event-forwarder \
  --assume-role-policy-document file://iam/forwarder-trust.json --tags Key=Project,Value=sg-monitor
aws iam put-role-policy --role-name sg-monitor-event-forwarder \
  --policy-name sg-monitor-forwarder --policy-document file://iam/forwarder-policy.json

sleep 15   # let IAM propagate before the Lambda uses the role
```

**Security note:** the Lambda can't change any Security Group, instance or the switch. It only reads.

---

## Step 7: Deploy the Lambda (5 min)

1. **Create the log group** with 30-day retention:
   ```bash
   aws logs create-log-group --log-group-name /aws/lambda/sg-monitor --region $HOME_REGION \
     --tags Project=sg-monitor
   aws logs put-retention-policy --log-group-name /aws/lambda/sg-monitor \
     --retention-in-days 30 --region $HOME_REGION
   ```

2. **Write the environment variables file.** Paste the Teams URL when asked:
   ```bash
   read -rsp "Paste the Teams webhook URL: " TEAMS_URL; echo; export TEAMS_URL
   python3 - <<PY > /tmp/env.json
   import json, os
   print(json.dumps({"Variables": {
       "TEAMS_WEBHOOK_URL": os.environ["TEAMS_URL"],
       "MONITORED_REGIONS": "$MONITORED_REGIONS",
       "SWITCH_PARAM_NAME": "/secops/sg-monitor/notify-status",
       "ALLOWLIST": "",
       "ALERT_ANY_PUBLIC_PORT": "false",
       "POST_WHEN_CLEAN": "true",
       "TZ_OFFSET_MINUTES": "330",
       "TZ_LABEL": "IST"
   }}))
   PY
   ```
   Check the file looks right without showing the URL: `python3 -c 'import json;v=json.load(open("/tmp/env.json"))["Variables"];print({k:(x if k!="TEAMS_WEBHOOK_URL" else x[:30]+"...") for k,x in v.items()})'`

3. **Package and create the function:**
   ```bash
   (cd lambda && zip -q ../function.zip lambda_function.py)
   aws lambda create-function --function-name sg-monitor --region $HOME_REGION \
     --runtime python3.13 --architectures arm64 \
     --handler lambda_function.lambda_handler \
     --role arn:aws:iam::$ACCOUNT_ID:role/sg-monitor-lambda-role \
     --zip-file fileb://function.zip \
     --timeout 180 --memory-size 256 \
     --environment file:///tmp/env.json \
     --tags Project=sg-monitor
   rm -f /tmp/env.json; unset TEAMS_URL           # do not leave the secret on disk
   ```

4. **Cap concurrency and set the failure path** (2 retries, then the dead-letter queue):
   ```bash
   aws lambda put-function-concurrency --function-name sg-monitor \
     --reserved-concurrent-executions 5 --region $HOME_REGION
   aws lambda put-function-event-invoke-config --function-name sg-monitor --region $HOME_REGION \
     --maximum-retry-attempts 2 --maximum-event-age-in-seconds 3600 \
     --destination-config "{\"OnFailure\":{\"Destination\":\"arn:aws:sqs:$HOME_REGION:$ACCOUNT_ID:sg-monitor-dlq\"}}"
   ```
   If `put-function-concurrency` fails with a limit error (common on new accounts), skip it. Everything else still works.

**Settings reference:**

| Variable | Meaning | Example |
|---|---|---|
| `MONITORED_REGIONS` | Regions for the daily and catch-up scans | `eu-west-2,ap-south-1,us-east-1` |
| `ALLOWLIST` | Ports allowed to be public: `<sg-id or *>:<port or range or *>` | `sg-0abc:443,sg-0abc:80,*:41641` |
| `CRITICAL_PORTS` | Overrides the built-in list of 31 sensitive ports | `22:SSH,3389:RDP,6379:Redis` |
| `ALERT_ANY_PUBLIC_PORT` | `true` also reports non-critical public ports | `false` |
| `POST_WHEN_CLEAN` | Post "✅ nothing open" on clean days (acts as a heartbeat) | `true` |

> ⚠️ `update-function-configuration --environment` **replaces all** variables. To change one, open the Console (**Lambda → sg-monitor → Configuration → Environment variables → Edit**) and edit just that one.
>
> 🔒 Anyone with `lambda:GetFunctionConfiguration` can read the webhook URL. Keep that permission, and `lambda:UpdateFunctionConfiguration`, limited to admins.

---

## Step 8: Wire up the triggers (5 min)

**8a. London rules: real-time SG events and switch changes, sent to the Lambda**
```bash
aws events put-rule --name sg-monitor-sg-events --region $HOME_REGION \
  --event-pattern file://eventbridge/sg-events-pattern.json --tags Key=Project,Value=sg-monitor
aws lambda add-permission --function-name sg-monitor --region $HOME_REGION \
  --statement-id eventbridge-sg-events --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:$HOME_REGION:$ACCOUNT_ID:rule/sg-monitor-sg-events
aws events put-targets --rule sg-monitor-sg-events --region $HOME_REGION \
  --targets file://eventbridge/london-sg-events-targets.json

aws events put-rule --name sg-monitor-switch-change --region $HOME_REGION \
  --event-pattern file://eventbridge/switch-change-pattern.json --tags Key=Project,Value=sg-monitor
aws lambda add-permission --function-name sg-monitor --region $HOME_REGION \
  --statement-id eventbridge-switch-change --action lambda:InvokeFunction \
  --principal events.amazonaws.com \
  --source-arn arn:aws:events:$HOME_REGION:$ACCOUNT_ID:rule/sg-monitor-switch-change
aws events put-targets --rule sg-monitor-switch-change --region $HOME_REGION \
  --targets file://eventbridge/london-switch-targets.json
```

**8b. Other server regions: forward SG events to London**
```bash
for R in $OTHER_REGIONS; do
  echo "== $R"
  aws events put-rule --name sg-monitor-forward-to-home --region $R \
    --event-pattern file://eventbridge/sg-events-pattern.json --tags Key=Project,Value=sg-monitor
  aws events put-targets --rule sg-monitor-forward-to-home --region $R \
    --targets file://eventbridge/forward-targets.json
done
```

**Optional hardening:** someone could create an open SG in a region you don't use. To catch that, also run 8b for every other enabled region:
```bash
aws ec2 describe-regions --query 'Regions[].RegionName' --output text
```
It's free, and the Lambda checks whichever region the event came from.

**8c. Schedules** (India time; IST has no daylight saving)
```bash
aws scheduler create-schedule --name sg-monitor-daily-scan --region $HOME_REGION \
  --schedule-expression "cron(0 10 * * ? *)" --schedule-expression-timezone "Asia/Kolkata" \
  --flexible-time-window '{"Mode":"OFF"}' --target file://scheduler/daily-scan-target.json

aws scheduler create-schedule --name sg-monitor-switch-report --region $HOME_REGION \
  --schedule-expression "cron(0 7,19 * * ? *)" --schedule-expression-timezone "Asia/Kolkata" \
  --flexible-time-window '{"Mode":"OFF"}' --target file://scheduler/switch-report-target.json
```

**Security note:** nobody can fake the real-time events. EventBridge refuses `PutEvents` calls that use an `aws.*` source, so only AWS itself can emit them. The Lambda's resource policy also allows only these two rules to invoke it, and the Scheduler role is the only other caller.

---

## Step 9: Alarms and budget (5 min)

These three alarms tell you by email when the monitoring itself breaks:
```bash
aws cloudwatch put-metric-alarm --region $HOME_REGION --alarm-name sg-monitor-lambda-errors \
  --namespace AWS/Lambda --metric-name Errors --dimensions Name=FunctionName,Value=sg-monitor \
  --statistic Sum --period 300 --evaluation-periods 1 --threshold 0 \
  --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching \
  --alarm-actions $SNS_ARN --tags Key=Project,Value=sg-monitor

aws cloudwatch put-metric-alarm --region $HOME_REGION --alarm-name sg-monitor-dlq-not-empty \
  --namespace AWS/SQS --metric-name ApproximateNumberOfMessagesVisible \
  --dimensions Name=QueueName,Value=sg-monitor-dlq \
  --statistic Maximum --period 300 --evaluation-periods 1 --threshold 0 \
  --comparison-operator GreaterThanThreshold --treat-missing-data notBreaching \
  --alarm-actions $SNS_ARN --tags Key=Project,Value=sg-monitor

aws cloudwatch put-metric-alarm --region $HOME_REGION --alarm-name sg-monitor-not-running \
  --namespace AWS/Lambda --metric-name Invocations --dimensions Name=FunctionName,Value=sg-monitor \
  --statistic Sum --period 86400 --evaluation-periods 1 --threshold 1 \
  --comparison-operator LessThanThreshold --treat-missing-data breaching \
  --alarm-actions $SNS_ARN --tags Key=Project,Value=sg-monitor
```

**Budget at $2/month, counting only this project's resources:**

1. **Activate the cost tag.** In the Billing console, go to **Cost allocation tags**, find **`Project`** under *User-defined*, and **Activate** it. It can take up to 24 hours to appear.
2. **Create the budget:**
   ```bash
   aws budgets create-budget --account-id $ACCOUNT_ID \
     --budget file://budget/budget.json \
     --notifications-with-subscribers file://budget/notifications.json
   ```
   If the CLI rejects the filter, create it in the console instead: **Budgets → Create → Cost budget → $2 monthly → Filter: Tag `Project` = `sg-monitor`**.

> ⚠️ Without the tag filter, the budget would track the **whole account**, including your servers, and email you every month.

---

## Step 10: Test every flow (15 min)

Run these in order and check the Teams channel after each one.

**T1: Daily scan.** Expect a "🛡️ Daily SG scan" card listing findings, or ✅ if nothing is open.
```bash
aws lambda invoke --function-name sg-monitor --region $HOME_REGION \
  --cli-binary-format raw-in-base64-out --payload '{"task":"daily_scan"}' /tmp/out.json && cat /tmp/out.json
```

**T2: Switch report.** Expect "✅ SG monitoring is active".
```bash
aws lambda invoke --function-name sg-monitor --region $HOME_REGION \
  --cli-binary-format raw-in-base64-out --payload '{"task":"switch_report"}' /tmp/out.json && cat /tmp/out.json
```

**T3: Real-time alert.** This uses a throwaway SG that isn't attached to anything, so nothing is actually exposed. Run it in one region from another region to also prove forwarding works; replace `ap-south-1` with one of your `OTHER_REGIONS`.
```bash
TR=ap-south-1
VPC=$(aws ec2 describe-vpcs --region $TR --query 'Vpcs[0].VpcId' --output text)
SG=$(aws ec2 create-security-group --region $TR --vpc-id $VPC --group-name sg-monitor-test \
      --description "sg-monitor test - delete me" --query GroupId --output text)
aws ec2 authorize-security-group-ingress --region $TR --group-id $SG --protocol tcp --port 22 --cidr 0.0.0.0/0
```
Within 1–2 minutes, expect **🟠 "Port opened to the internet"** with: your IAM user name, `22 (SSH)`, and *"Not attached to any server yet"*.

**T4: Pause, change during the pause, resume.**
1. **Pause.** Run the **OFF** command from `SRE_RUNBOOK.md` with reason `test`. Expect **⏸️ PAUSED by \<you\>**.
2. **Make a change while paused:**
   ```bash
   aws ec2 authorize-security-group-ingress --region $TR --group-id $SG --protocol tcp --port 3306 --cidr 0.0.0.0/0
   ```
   No Teams alert should appear. The logs should show the skip:
   ```bash
   aws logs tail /aws/lambda/sg-monitor --since 10m --region $HOME_REGION | grep SKIPPED
   ```
3. **Report while paused.** Run the T2 command again. Expect "⚠️ Maintenance is going on from the past 0h Xm…".
4. **Resume.** Wait about 15 minutes (CloudTrail history lag), then run the **ON** command. Expect **▶️ RESUMED** with:
   - the pause duration
   - the 3306 change listed under "Changes made during the pause"
   - a catch-up scan showing the test SG's 22 and 3306 rules

**T5: Clean up.**
```bash
aws ec2 delete-security-group --region $TR --group-id $SG
```

**T6: Failure path (optional).** In the Lambda console, temporarily change `TEAMS_WEBHOOK_URL` to `https://example.invalid/x` and run T2.
- Expect the **sg-monitor-lambda-errors** alarm email within about 5 minutes.
- After the retries, a message lands in the dead-letter queue and **sg-monitor-dlq-not-empty** fires as well.
- Restore the URL afterwards and purge the queue:
  ```bash
  aws sqs purge-queue --queue-url $DLQ_URL --region $HOME_REGION
  ```

---

## Updating the code later

```bash
cd ~/sg-monitor && (cd lambda && rm -f ../function.zip && zip -q ../function.zip lambda_function.py)
aws lambda update-function-code --function-name sg-monitor --zip-file fileb://function.zip --region $HOME_REGION
```

## Troubleshooting

| Symptom | Check |
|---|---|
| No real-time alert at all | Is the trail logging (Step 1)? Is the switch `ON`? In **EventBridge → Rules → sg-monitor-sg-events → Monitoring**, are there *Matched events*? |
| Alerts for the London region only | The forwarding rules from 8b are missing in the other regions, or the `sg-monitor-event-forwarder` role is wrong. Check *FailedInvocations* on the forwarding rule. |
| Rule matched but nothing in Teams | Search the Lambda logs for `RuntimeError`. Is the webhook URL correct, and is the Teams workflow still turned on and owned by an active account? |
| `AccessDenied` in the logs | Compare the role policy with `iam/lambda-policy.json`. |
| Report says "switch MISSING" | Re-run Step 3. |
| Daily scan says "Could not scan: \<region\>" | The region is disabled for the account, or there's an IAM problem. The message shows the error code. |
| A legitimate public port keeps alerting | Add it to `ALLOWLIST`, for example `sg-0abc123:443`. |
| A duplicate alert now and then | Expected: EventBridge delivers at least once. |

## Monthly cost (eu-west-2, about 3 maintenance pauses a month)

| Item | Cost |
|---|---|
| Lambda (about 1,100 invocations, 600 GB-seconds) | ~$0.01 |
| EventBridge rules, AWS events, Scheduler, cross-region forwarding | ~$0.00 |
| SSM Standard parameter, CloudTrail LookupEvents | $0.00 |
| CloudWatch Logs (30 days) + 3 alarms | ~$0.31 (alarms are free within the free tier of 10) |
| SQS / SNS | ~$0.00 |
| CloudTrail trail, only if newly created (S3 writes + storage with a 90-day expiry) | ~$0.20–0.40 |
| **Total** | **≈ $0.30–0.75 / month** |

These are list prices. Before sign-off, confirm them in the AWS Pricing Calculator for eu-west-2.

## Rollback (remove everything)

```bash
aws scheduler delete-schedule --name sg-monitor-daily-scan --region $HOME_REGION
aws scheduler delete-schedule --name sg-monitor-switch-report --region $HOME_REGION
for R in $OTHER_REGIONS; do
  aws events remove-targets --rule sg-monitor-forward-to-home --ids forward-to-home-region --region $R
  aws events delete-rule --name sg-monitor-forward-to-home --region $R
done
for RULE in sg-monitor-sg-events sg-monitor-switch-change; do
  aws events remove-targets --rule $RULE --ids sg-monitor-lambda --region $HOME_REGION
  aws events delete-rule --name $RULE --region $HOME_REGION
done
aws lambda delete-function --function-name sg-monitor --region $HOME_REGION
aws cloudwatch delete-alarms --alarm-names sg-monitor-lambda-errors sg-monitor-dlq-not-empty sg-monitor-not-running --region $HOME_REGION
aws sqs delete-queue --queue-url $DLQ_URL --region $HOME_REGION
aws sns delete-topic --topic-arn $SNS_ARN --region $HOME_REGION
aws ssm delete-parameter --name /secops/sg-monitor/notify-status --region $HOME_REGION
aws budgets delete-budget --account-id $ACCOUNT_ID --budget-name sg-monitor-monthly
# IAM roles and group: detach/delete their inline policies first, then delete-role / delete-group.
# CloudTrail trail and bucket: delete only if this guide created them.
```
