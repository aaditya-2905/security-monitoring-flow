# Edit the three EDIT lines, then run:  source config/vars.sh
# Re-run it whenever CloudShell restarts (variables are lost on timeout).
export HOME_REGION="eu-west-2"
export SERVER_REGIONS="eu-west-2 ap-south-1 us-east-1"      # EDIT: the 3 regions your servers run in
export ALERT_EMAIL="sre-team@yourcompany.com"               # EDIT: email for alarms and the budget
export SRE_USERS="user1 user2"                              # EDIT: IAM user names allowed to flip the switch

export ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
export LAMBDA_ARN="arn:aws:lambda:${HOME_REGION}:${ACCOUNT_ID}:function:sg-monitor"
export DLQ_URL="https://sqs.${HOME_REGION}.amazonaws.com/${ACCOUNT_ID}/sg-monitor-dlq"
export SNS_ARN="arn:aws:sns:${HOME_REGION}:${ACCOUNT_ID}:sg-monitor-ops"
export OTHER_REGIONS="$(for r in $SERVER_REGIONS; do [ "$r" != "$HOME_REGION" ] && printf '%s ' "$r"; done)"
export MONITORED_REGIONS="$(echo $SERVER_REGIONS | tr ' ' ',')"
echo "Account $ACCOUNT_ID | home $HOME_REGION | monitored $MONITORED_REGIONS | forwarding from: ${OTHER_REGIONS:-none}"
