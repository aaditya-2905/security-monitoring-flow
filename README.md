# SG Monitor

Alerts a Microsoft Teams channel whenever an AWS Security Group exposes a sensitive port to the internet. It runs entirely on managed AWS services (CloudTrail, EventBridge, Scheduler, SSM, Lambda, SQS, SNS), needs no agents on servers, and costs roughly **$0.30–0.75 a month**.

## How it works

```
Other server regions                    Home region (eu-west-2)
CloudTrail → EventBridge ──forward──►   EventBridge rules + Scheduler
                                                   │
                                                   ▼
                                        Lambda "sg-monitor" (read-only)
                                        reads switch: SSM /secops/sg-monitor/notify-status
                                                   │                  │ on failure
                                                   ▼                  ▼
                                        Teams Workflow webhook   SQS DLQ + CloudWatch alarms → SNS email
```

| Flow | Trigger | What it does |
|---|---|---|
| Daily scan | 10:00 IST | Scans every SG in the monitored regions. Always runs, even while paused. Posts findings, or "✅ nothing open" as a heartbeat. |
| Real-time check | SG / ENI / instance / public IP change | Alerts when a critical port becomes reachable from the internet, naming the IAM user who did it. Skipped while the switch is `OFF`. |
| Switch report | 07:00 and 19:00 IST | Reports whether monitoring is active or how long maintenance has been running. |
| Switch change | An SRE flips the switch | Announces pause/resume; on resume, lists SG changes made during the pause and runs a catch-up scan. |

**Fail-safe:** anything other than a readable, exact `OFF` in the switch is treated as `ON`, so a broken switch can never silence alerts.

## Repository layout

| Path | Contents |
|---|---|
| [lambda/lambda_function.py](lambda/lambda_function.py) | The single Lambda function (Python 3.13, stdlib + boto3 only) |
| [tests/test_lambda.py](tests/test_lambda.py) | Offline unit tests with in-memory AWS fakes |
| [config/vars.sh](config/vars.sh) | Deployment variables (regions, alert email, SRE users) |
| [iam/](iam/) | Trust and permission policies for the Lambda, Scheduler, forwarder, DLQ and SRE group |
| [eventbridge/](eventbridge/) | Event patterns and rule targets |
| [scheduler/](scheduler/) | Targets for the daily scan and switch report schedules |
| [cloudtrail/](cloudtrail/) | Bucket policy and lifecycle, used only if a new trail is created |
| [budget/](budget/) | $2/month cost budget filtered on the `Project=sg-monitor` tag |
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Step-by-step setup in AWS CloudShell (~45 min) |
| [SRE_RUNBOOK.md](SRE_RUNBOOK.md) | How SREs pause and resume alerts during maintenance |

## Getting started

1. Follow [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md). In short: edit the `EDIT` lines in `config/vars.sh`, `source` it in CloudShell, fill the `<ACCOUNT_ID>` / `<HOME_REGION>` / `<ALERT_EMAIL>` placeholders, then create the switch, IAM roles, Lambda, triggers, alarms and budget.
2. Share [SRE_RUNBOOK.md](SRE_RUNBOOK.md) with the team that performs maintenance.

## Configuration

Set as Lambda environment variables (full reference in the docstring of `lambda_function.py`):

| Variable | Default | Meaning |
|---|---|---|
| `TEAMS_WEBHOOK_URL` | required | Teams Workflows webhook URL. **Treat as a secret.** |
| `MONITORED_REGIONS` | home region | Comma-separated regions for daily and catch-up scans |
| `SWITCH_PARAM_NAME` | `/secops/sg-monitor/notify-status` | SSM parameter holding `ON` / `OFF` |
| `CRITICAL_PORTS` | built-in list of 31 ports | Override, e.g. `22:SSH,3389:RDP,6379` |
| `ALLOWLIST` | empty | Ports allowed to be public, e.g. `sg-0abc:443,*:41641,sg-0def:8000-8100` |
| `ALERT_ANY_PUBLIC_PORT` | `false` | Also report non-critical public ports |
| `POST_WHEN_CLEAN` | `true` | Post a message on clean days (heartbeat) |
| `TZ_OFFSET_MINUTES` / `TZ_LABEL` | `330` / `IST` | Time zone used in messages |

## Running the tests

No AWS account or credentials are needed:

```bash
python3 -m unittest discover -s tests -v
```

## Updating the Lambda

```bash
source config/vars.sh
(cd lambda && rm -f ../function.zip && zip -q ../function.zip lambda_function.py)
aws lambda update-function-code --function-name sg-monitor --zip-file fileb://function.zip --region $HOME_REGION
```

## Security notes

- The Lambda is **read-only**: it cannot change Security Groups, instances or the switch.
- Only the two EventBridge rules and the Scheduler role can invoke it; `aws.*` events cannot be forged via `PutEvents`.
- Never commit the Teams webhook URL. Restrict `lambda:GetFunctionConfiguration` and `lambda:UpdateFunctionConfiguration` to admins, since they expose or change it.
