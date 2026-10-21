"""
SG Monitor - one Lambda that alerts Microsoft Teams about Security Group exposure.

Triggers (routed in lambda_handler):
  1. EventBridge Scheduler {"task": "daily_scan"}      10:00 IST full scan. Always runs, ignores the switch.
  2. EventBridge Scheduler {"task": "switch_report"}   07:00 / 19:00 IST switch status report.
  3. EventBridge rule, CloudTrail event (aws.ec2)       Real-time SG check. Skipped while the switch is OFF.
  4. EventBridge rule, Parameter Store Change (aws.ssm) Switch flipped: pause notice / resume + catch-up scan.

The switch is the SSM parameter SWITCH_PARAM_NAME ("ON" / "OFF"). Anything other than an exact,
readable "OFF" is treated as ON (fail-safe), so a broken switch can never silence alerts.

Environment variables:
  TEAMS_WEBHOOK_URL       (required) Teams Workflows "webhook request received" URL.
  MONITORED_REGIONS       (required) Comma-separated regions for the daily / catch-up scans.
  SWITCH_PARAM_NAME       default /secops/sg-monitor/notify-status
  CRITICAL_PORTS          optional override, e.g. "22:SSH,3389:RDP,6379" (name optional).
  ALLOWLIST               optional, e.g. "sg-0abc:443,sg-0abc:80,*:41641,sg-0def:8000-8100".
  ALERT_ANY_PUBLIC_PORT   "true" to also report non-critical ports open to the internet. Default false.
  POST_WHEN_CLEAN         "false" to skip the daily message when nothing is open. Default true.
  TZ_OFFSET_MINUTES       default 330 (IST, UTC+05:30, no DST).
  TZ_LABEL                default IST.
"""

import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# --------------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------------

HOME_REGION = os.environ.get("AWS_REGION", "eu-west-2")
SWITCH_PARAM = os.environ.get("SWITCH_PARAM_NAME", "/secops/sg-monitor/notify-status")


def _env_bool(name, default):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _env_list(name, default=""):
    return [x.strip() for x in os.environ.get(name, default).split(",") if x.strip()]


MONITORED_REGIONS = _env_list("MONITORED_REGIONS", HOME_REGION)
ALERT_ANY_PUBLIC_PORT = _env_bool("ALERT_ANY_PUBLIC_PORT", False)
POST_WHEN_CLEAN = _env_bool("POST_WHEN_CLEAN", True)
TZ = timezone(timedelta(minutes=int(os.environ.get("TZ_OFFSET_MINUTES", "330"))))
TZ_LABEL = os.environ.get("TZ_LABEL", "IST")

MAX_FINDINGS_IN_CARD = 25
MAX_CHANGES_IN_CARD = 20

DEFAULT_CRITICAL_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS", 2375: "Docker API", 2376: "Docker API TLS",
    2379: "etcd", 2380: "etcd peer", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5601: "Kibana", 5672: "RabbitMQ", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    8086: "InfluxDB", 9042: "Cassandra", 9092: "Kafka", 9200: "Elasticsearch",
    9300: "Elasticsearch transport", 10250: "Kubelet", 11211: "Memcached",
    15672: "RabbitMQ admin", 2181: "ZooKeeper", 27017: "MongoDB",
}


def _parse_critical_ports(raw):
    if not raw.strip():
        return dict(DEFAULT_CRITICAL_PORTS)
    ports = {}
    for item in _env_list("CRITICAL_PORTS"):
        port, _, name = item.partition(":")
        p = int(port)
        ports[p] = name.strip() or DEFAULT_CRITICAL_PORTS.get(p, f"port {p}")
    return ports


CRITICAL_PORTS = _parse_critical_ports(os.environ.get("CRITICAL_PORTS", ""))


def _parse_allowlist(items):
    """'sg-0abc:443' / '*:41641' / 'sg-0abc:8000-8100' / 'sg-0abc:*' -> [(sg_or_*, lo, hi)]"""
    entries = []
    for item in items:
        sg, _, spec = item.partition(":")
        spec = spec.strip() or "*"
        if spec == "*":
            lo, hi = 0, 65535
        elif "-" in spec:
            lo, hi = (int(x) for x in spec.split("-", 1))
        else:
            lo = hi = int(spec)
        entries.append((sg.strip(), lo, hi))
    return entries


ALLOWLIST = _parse_allowlist(_env_list("ALLOWLIST"))

# CloudTrail events that can open or expose a port. Must match eventbridge/sg-events-pattern.json.
RULE_EVENTS = {"AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"}
ATTACH_EVENTS = {"ModifyNetworkInterfaceAttribute", "ModifyInstanceAttribute"}
SG_EVENTS = RULE_EVENTS | ATTACH_EVENTS | {
    "CreateNetworkInterface", "RunInstances", "AssociateAddress", "ModifyManagedPrefixList",
}
# Looked up in CloudTrail history to summarise what changed during a maintenance pause.
PAUSE_LOOKUP_EVENTS = sorted(SG_EVENTS | {"RevokeSecurityGroupIngress", "CreateSecurityGroup",
                                           "DeleteSecurityGroup"})

_BOTO_CFG = Config(retries={"max_attempts": 8, "mode": "adaptive"},
                   connect_timeout=5, read_timeout=20)
_clients = {}


def client(service, region=HOME_REGION):
    key = (service, region)
    if key not in _clients:
        _clients[key] = boto3.client(service, region_name=region, config=_BOTO_CFG)
    return _clients[key]


# --------------------------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------------------------

def log(message, **fields):
    print(json.dumps({"msg": message, **fields}, default=str))


def fmt_time(dt):
    if dt is None:
        return "unknown time"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(TZ).strftime("%d %b %Y, %H:%M ") + TZ_LABEL


def fmt_duration(delta):
    minutes = max(int(delta.total_seconds() // 60), 0)
    days, rem = divmod(minutes, 1440)
    hours, mins = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {mins}m"
    return f"{hours}h {mins}m"


def now_utc():
    return datetime.now(timezone.utc)


def parse_iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


_UNSAFE_CHARS = re.compile(r"[\[\]()*_`<>#~|\\{}]")


def clean(value, limit=200):
    """Neutralise user-controlled text (SG names, descriptions, tags, reasons) before it goes
    into a Teams card: no markdown, no clickable links, single line, bounded length."""
    s = "" if value is None else str(value)
    s = _UNSAFE_CHARS.sub("", s)
    s = re.sub(r"(?i)(https?|ftp)://", r"\1[:]//", s)
    s = re.sub(r"(?i)www\.", "www[.]", s)
    s = " ".join(s.split())
    return s if len(s) <= limit else s[: limit - 1] + "..."


def actor_from_arn(arn):
    if not arn:
        return "unknown"
    if arn.endswith(":root"):
        return "ROOT ACCOUNT"
    m = re.search(r":user/(?:.*/)?([^/]+)$", arn)
    if m:
        return m.group(1)
    m = re.search(r":assumed-role/([^/]+)/(.+)$", arn)
    if m:
        return f"{m.group(2)} (role {m.group(1)})"
    return arn


def actor_from_identity(identity):
    identity = identity or {}
    kind = identity.get("type")
    if kind == "Root":
        return "ROOT ACCOUNT"
    if kind == "IAMUser":
        return identity.get("userName") or actor_from_arn(identity.get("arn"))
    if kind == "AWSService":
        return f"AWS service ({identity.get('invokedBy', 'unknown')})"
    return actor_from_arn(identity.get("arn")) if identity.get("arn") else (kind or "unknown")


def access_channel(detail):
    ua = (detail.get("userAgent") or "").lower()
    ctx = detail.get("sessionCredentialFromConsole")
    if "cloudshell" in ua:
        return "AWS CloudShell"
    if ctx == "true" or ua in ("console.amazonaws.com", "signin.amazonaws.com") or "console" in ua:
        return "AWS Console"
    if "terraform" in ua:
        return "Terraform"
    if "aws-cli" in ua:
        return "AWS CLI"
    if "cloudformation" in ua:
        return "CloudFormation"
    return "API / SDK"


_ID_PATTERNS = {
    "sg": re.compile(r"^sg-[0-9a-f]{8,17}$"),
    "sgr": re.compile(r"^sgr-[0-9a-f]{8,17}$"),
    "eni": re.compile(r"^eni-[0-9a-f]{8,17}$"),
    "i": re.compile(r"^i-[0-9a-f]{8,17}$"),
    "pl": re.compile(r"^pl-[0-9a-f]{8,17}$"),
}


def extract_ids(obj, out=None):
    """Collect AWS resource IDs anywhere in a CloudTrail request/response. Walking the whole
    structure is more robust than depending on each API's exact field layout."""
    if out is None:
        out = {k: set() for k in _ID_PATTERNS}
    if isinstance(obj, dict):
        for v in obj.values():
            extract_ids(v, out)
    elif isinstance(obj, list):
        for v in obj:
            extract_ids(v, out)
    elif isinstance(obj, str):
        for kind, pattern in _ID_PATTERNS.items():
            if pattern.match(obj):
                out[kind].add(obj)
    return out


# --------------------------------------------------------------------------------------------
# "Open to the internet" + port logic
# --------------------------------------------------------------------------------------------

_V4_NOT_WORLD = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "127.0.0.0/8", "0.0.0.0/8")]
_V6_NOT_WORLD = [ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10")]


def is_world(cidr):
    """True for 0.0.0.0/0, ::/0 and any very broad public range (IPv4 /8 or wider, IPv6 /16 or
    wider), so splitting 0.0.0.0/0 into 0.0.0.0/1 + 128.0.0.0/1 does not evade detection."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    if net.version == 4:
        return net.prefixlen <= 8 and not any(net.subnet_of(x) for x in _V4_NOT_WORLD)
    return net.prefixlen <= 16 and not any(net.subnet_of(x) for x in _V6_NOT_WORLD)


def port_allowlisted(sg_id, port):
    return any(sg in (sg_id, "*") and lo <= port <= hi for sg, lo, hi in ALLOWLIST)


def range_allowlisted(sg_id, lo, hi):
    return any(sg in (sg_id, "*") and a <= lo and hi <= b for sg, a, b in ALLOWLIST)


def rule_port_range(rule):
    """(protocol label, lo, hi) or None for protocols that carry no ports (ICMP etc.)."""
    proto = str(rule.get("IpProtocol", "")).lower()
    if proto in ("-1", "all"):
        return "ALL traffic", 0, 65535
    if proto in ("tcp", "6", "udp", "17"):
        lo, hi = rule.get("FromPort"), rule.get("ToPort")
        if lo is None or lo == -1:
            lo, hi = 0, 65535
        label = "TCP" if proto in ("tcp", "6") else "UDP"
        return label, int(lo), int(hi)
    return None


# --------------------------------------------------------------------------------------------
# Regional inventory (security groups, rules, ENIs, instances, prefix lists)
# --------------------------------------------------------------------------------------------

def _chunks(items, size=50):
    items = list(items)
    for i in range(0, len(items), size):
        yield items[i:i + size]


class Inventory:
    """Loads what one region needs, lazily, once per invocation."""

    def __init__(self, region):
        self.region = region
        self.ec2 = client("ec2", region)
        self._attachments = None
        self._group_names = {}
        self._prefix_lists = {}

    def _paginate(self, op, key, **kwargs):
        for page in self.ec2.get_paginator(op).paginate(**kwargs):
            yield from page.get(key, [])

    def ingress_rules(self, sg_ids=None):
        if sg_ids is None:
            rules = list(self._paginate("describe_security_group_rules", "SecurityGroupRules"))
        else:
            rules = []
            for chunk in _chunks(sg_ids):
                rules += self._paginate("describe_security_group_rules", "SecurityGroupRules",
                                        Filters=[{"Name": "group-id", "Values": chunk}])
        return [r for r in rules if not r.get("IsEgress")]

    def load_group_names(self, sg_ids=None):
        if sg_ids is None:
            groups = self._paginate("describe_security_groups", "SecurityGroups")
        else:
            groups = []
            for chunk in _chunks(sg_ids):
                groups += self._paginate("describe_security_groups", "SecurityGroups",
                                         Filters=[{"Name": "group-id", "Values": chunk}])
        for g in groups:
            self._group_names[g["GroupId"]] = g.get("GroupName", "")

    def group_name(self, sg_id):
        return self._group_names.get(sg_id, "")

    def groups_referencing_prefix_list(self, pl_id):
        groups = self._paginate("describe_security_groups", "SecurityGroups",
                                Filters=[{"Name": "ip-permission.prefix-list-id", "Values": [pl_id]}])
        return {g["GroupId"] for g in groups}

    def prefix_list_world_cidr(self, pl_id):
        if pl_id not in self._prefix_lists:
            found = None
            try:
                for entry in self._paginate("get_managed_prefix_list_entries", "Entries",
                                            PrefixListId=pl_id):
                    if is_world(entry.get("Cidr", "")):
                        found = entry["Cidr"]
                        break
            except ClientError as e:
                log("prefix_list_lookup_failed", region=self.region, prefix_list=pl_id,
                    error=e.response.get("Error", {}).get("Code"))
            self._prefix_lists[pl_id] = found
        return self._prefix_lists[pl_id]

    def attachments(self):
        """sg_id -> [resource dicts] for every ENI in the region (instances, RDS, ELB, ...)."""
        if self._attachments is not None:
            return self._attachments
        names = {}
        for res in self._paginate("describe_instances", "Reservations"):
            for inst in res.get("Instances", []):
                tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                names[inst["InstanceId"]] = tags.get("Name", "")
        by_sg = {}
        self._eni_groups, self._instance_groups = {}, {}
        for eni in self._paginate("describe_network_interfaces", "NetworkInterfaces"):
            instance_id = (eni.get("Attachment") or {}).get("InstanceId")
            groups = [g["GroupId"] for g in eni.get("Groups", [])]
            resource = {
                "id": instance_id or eni["NetworkInterfaceId"],
                "name": names.get(instance_id, "") if instance_id else (eni.get("Description") or eni.get("InterfaceType") or ""),
                "private_ip": eni.get("PrivateIpAddress", ""),
                "public_ipv4": (eni.get("Association") or {}).get("PublicIp"),
                "ipv6": [a["Ipv6Address"] for a in eni.get("Ipv6Addresses", []) if a.get("Ipv6Address")],
            }
            self._eni_groups[eni["NetworkInterfaceId"]] = set(groups)
            if instance_id:
                self._instance_groups.setdefault(instance_id, set()).update(groups)
            for g in groups:
                by_sg.setdefault(g, []).append(resource)
        self._attachments = by_sg
        return by_sg

    def groups_of_instance(self, instance_id):
        self.attachments()
        return set(self._instance_groups.get(instance_id, set()))

    def groups_of_eni(self, eni_id):
        self.attachments()
        return set(self._eni_groups.get(eni_id, set()))


def world_source(rule, inv):
    """Return (source text, ip family) if the rule admits the internet, else None."""
    if rule.get("CidrIpv4") and is_world(rule["CidrIpv4"]):
        return rule["CidrIpv4"], 4
    if rule.get("CidrIpv6") and is_world(rule["CidrIpv6"]):
        return rule["CidrIpv6"], 6
    pl = rule.get("PrefixListId")
    if pl:
        cidr = inv.prefix_list_world_cidr(pl)
        if cidr:
            family = 6 if ":" in cidr else 4
            return f"{cidr} (via prefix list {pl})", family
    return None


def evaluate(inv, sg_ids=None):
    """Findings for every ingress rule that opens a critical port (or, optionally, any port)
    to the internet, with which servers are actually reachable through it."""
    rules = inv.ingress_rules(sg_ids)
    inv.load_group_names(sg_ids)
    attached = inv.attachments()
    findings = []
    for rule in rules:
        src = world_source(rule, inv)
        rng = rule_port_range(rule)
        if not src or not rng:
            continue
        source, family = src
        proto, lo, hi = rng
        sg_id = rule["GroupId"]
        open_critical = [p for p in sorted(CRITICAL_PORTS) if lo <= p <= hi and not port_allowlisted(sg_id, p)]
        if open_critical:
            kind = "critical"
        elif ALERT_ANY_PUBLIC_PORT and not range_allowlisted(sg_id, lo, hi):
            kind = "public"
        else:
            continue

        resources = attached.get(sg_id, [])
        exposed = [r for r in resources if (r["public_ipv4"] if family == 4 else r["ipv6"])]
        if exposed:
            severity = "CRITICAL" if kind == "critical" else "HIGH"
            exposure = "Reachable from the internet"
        elif resources:
            severity = "HIGH" if kind == "critical" else "MEDIUM"
            exposure = "Attached servers have no public IP (not reachable right now)"
        else:
            severity = "HIGH" if kind == "critical" else "MEDIUM"
            exposure = "Not attached to any server yet"

        findings.append({
            "region": inv.region,
            "sg_id": sg_id,
            "sg_name": inv.group_name(sg_id),
            "rule_id": rule.get("SecurityGroupRuleId", ""),
            "protocol": proto,
            "ports": "all ports" if (lo, hi) == (0, 65535) else (str(lo) if lo == hi else f"{lo}-{hi}"),
            "critical": [f"{p} ({CRITICAL_PORTS[p]})" for p in open_critical],
            "source": source,
            "rule_description": rule.get("Description", ""),
            "severity": severity,
            "exposure": exposure,
            "resources": exposed or resources,
        })
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["region"], f["sg_id"]))
    return findings


def scan_all_regions():
    findings, errors = [], []
    for region in MONITORED_REGIONS:
        try:
            findings += evaluate(Inventory(region))
        except Exception as e:  # one broken region must not hide the others
            code = e.response.get("Error", {}).get("Code") if isinstance(e, ClientError) else type(e).__name__
            errors.append(f"{region}: {code}")
            log("region_scan_failed", region=region, error=str(e))
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["region"], f["sg_id"]))
    return findings, errors


# --------------------------------------------------------------------------------------------
# The ON/OFF switch (SSM Parameter Store)
# --------------------------------------------------------------------------------------------

def read_switch():
    """Always read fresh (no caching across invocations). Fail-safe: anything but a readable,
    exact "OFF" means alerts stay ON."""
    try:
        value = client("ssm").get_parameter(Name=SWITCH_PARAM)["Parameter"]["Value"]
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        state = "MISSING" if code == "ParameterNotFound" else "ERROR"
        log("switch_read_problem", state=state, error=code)
        return {"state": state, "on": True, "detail": code}
    except Exception as e:
        log("switch_read_problem", state="ERROR", error=str(e))
        return {"state": "ERROR", "on": True, "detail": type(e).__name__}
    if value == "ON":
        return {"state": "ON", "on": True}
    if value == "OFF":
        return {"state": "OFF", "on": False}
    return {"state": "INVALID", "on": True, "detail": clean(value, 40)}


def switch_history():
    ssm = client("ssm")
    versions, kwargs = [], {"Name": SWITCH_PARAM, "MaxResults": 50}
    while True:
        resp = ssm.get_parameter_history(**kwargs)
        versions += resp.get("Parameters", [])
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    versions.sort(key=lambda v: v["Version"])
    return versions


def _fresh_reason(versions, idx):
    """Description of versions[idx] only if it was changed in that version; a description
    carried over from an earlier change is not a reason for this one."""
    desc = (versions[idx].get("Description") or "").strip()
    prev = (versions[idx - 1].get("Description") or "").strip() if idx > 0 else None
    return clean(desc) if desc and desc != prev else None


def _streak_start(versions, end_idx, value):
    i = end_idx
    while i > 0 and versions[i - 1].get("Value") == value:
        i -= 1
    return i


def pause_info(versions, end_idx=None):
    """Who/when/why for the OFF streak that ends at end_idx (default: the latest version)."""
    if end_idx is None:
        end_idx = len(versions) - 1
    start = _streak_start(versions, end_idx, "OFF")
    reason = None
    for j in range(end_idx, start - 1, -1):  # newest reason given during the pause wins
        reason = _fresh_reason(versions, j)
        if reason:
            break
    first = versions[start]
    return {
        "by": actor_from_arn(first.get("LastModifiedUser")),
        "at": first.get("LastModifiedDate"),
        "reason": reason,
    }


def switch_banner(switch):
    """One line for cards whose behaviour depends on the switch, or None when it is plainly ON."""
    if switch["state"] == "OFF":
        return "⚠️ Maintenance mode is ON: real-time SG alerts are paused. This scan still runs."
    if switch["state"] != "ON":
        return (f"🔴 Alert switch is {switch['state']} ({switch.get('detail', '')}). "
                "Treating it as ON (fail-safe). Fix the switch parameter.")
    return None


# --------------------------------------------------------------------------------------------
# Teams output (Workflows webhook -> Adaptive Card)
# --------------------------------------------------------------------------------------------

def tb(text, **kw):
    return {"type": "TextBlock", "text": text, "wrap": True, **kw}


def facts(pairs):
    return {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in pairs if v]}


def title_block(text, color):
    return tb(text, size="Large", weight="Bolder", color=color)


def finding_blocks(findings, limit=MAX_FINDINGS_IN_CARD):
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}
    blocks = []
    for f in findings[:limit]:
        what = ", ".join(f["critical"]) if f["critical"] else f"{f['protocol']} {f['ports']}"
        servers = "; ".join(
            f"{clean(r['name'], 60) or r['id']} ({r['id']}"
            + (f", public {r['public_ipv4']}" if r.get("public_ipv4") else "")
            + (f", private {r['private_ip']}" if r.get("private_ip") else "") + ")"
            for r in f["resources"][:5]
        ) or "none"
        if len(f["resources"]) > 5:
            servers += f"; +{len(f['resources']) - 5} more"
        blocks.append({
            "type": "Container", "separator": True, "items": [
                tb(f"{icon[f['severity']]} **{f['severity']}**: {what} open to {clean(f['source'], 80)}",
                   weight="Bolder"),
                facts([
                    ("Region", f["region"]),
                    ("Security group", f"{f['sg_id']} ({clean(f['sg_name'], 80)})" if f["sg_name"] else f["sg_id"]),
                    ("Rule", f"{f['rule_id']} · {f['protocol']} {f['ports']}"),
                    ("Rule note", clean(f["rule_description"], 120)),
                    ("Exposure", f["exposure"]),
                    ("Servers", servers),
                ]),
            ],
        })
    if len(findings) > limit:
        blocks.append(tb(f"... and {len(findings) - limit} more. Check the Lambda logs for the full list.",
                         isSubtle=True))
    return blocks


def post_to_teams(body):
    url = os.environ.get("TEAMS_WEBHOOK_URL", "")
    if not url.startswith("https://"):
        raise RuntimeError("TEAMS_WEBHOOK_URL is missing or not https")
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "msteams": {"width": "Full"},
                "body": body,
            },
        }],
    }
    data = json.dumps(payload).encode("utf-8")
    last_error = None
    for attempt in range(3):
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                if 200 <= resp.status < 300:
                    return
                last_error = f"HTTP {resp.status}"
        except urllib.error.HTTPError as e:
            last_error = f"HTTP {e.code}"
            if e.code not in (408, 429, 500, 502, 503, 504):
                break
        except urllib.error.URLError as e:
            last_error = f"network error: {e.reason}"
        time.sleep(2 ** attempt)
    # Never include the URL itself: it is a secret.
    raise RuntimeError(f"Teams webhook post failed ({last_error})")


# --------------------------------------------------------------------------------------------
# Flow 1: daily scan (10:00 IST) - always runs, ignores the switch
# --------------------------------------------------------------------------------------------

def run_daily_scan():
    switch = read_switch()
    findings, errors = scan_all_regions()
    log("daily_scan", findings=len(findings), errors=errors, switch=switch["state"],
        details=findings)
    if not findings and not errors and not POST_WHEN_CLEAN:
        return {"status": "clean", "posted": False}

    crit = sum(f["severity"] == "CRITICAL" for f in findings)
    if crit:
        title, color = f"🛡️ Daily SG scan: {crit} CRITICAL exposure(s)", "Attention"
    elif findings:
        title, color = f"🛡️ Daily SG scan: {len(findings)} open port finding(s)", "Warning"
    elif errors:
        title, color = "🛡️ Daily SG scan: ⚠️ incomplete, some regions could not be scanned", "Attention"
    else:
        title, color = "🛡️ Daily SG scan: ✅ no critical ports open to the internet", "Good"

    body = [title_block(title, color),
            tb(f"{fmt_time(now_utc())} · Regions: {', '.join(MONITORED_REGIONS)}", isSubtle=True)]
    banner = switch_banner(switch)
    if banner:
        body.append(tb(banner, color="Warning", weight="Bolder"))
    if errors:
        body.append(tb("🔴 Could not scan: " + "; ".join(errors) + ". Results for these regions are missing.",
                       color="Attention", weight="Bolder"))
    body += finding_blocks(findings)
    post_to_teams(body)
    return {"status": "posted", "findings": len(findings), "errors": errors}


# --------------------------------------------------------------------------------------------
# Flow 3: switch status report (07:00 / 19:00 IST)
# --------------------------------------------------------------------------------------------

def run_switch_report():
    switch = read_switch()
    body = []
    if switch["state"] == "OFF":
        try:
            info = pause_info(switch_history())
            since = fmt_duration(now_utc() - info["at"]) if info["at"] else "an unknown time"
            body = [
                title_block(f"⚠️ Maintenance is going on from the past {since}. Please be aware.", "Warning"),
                facts([
                    ("Paused by", clean(info["by"])),
                    ("Paused at", fmt_time(info["at"])),
                    ("Reason", info["reason"] or "no reason given"),
                    ("Status", "Real-time SG alerts are OFF for all regions. The 10:00 daily scan still runs."),
                ]),
            ]
        except Exception as e:
            log("switch_history_failed", error=str(e))
            body = [title_block("⚠️ Maintenance mode is ON: real-time SG alerts are paused. Please be aware.", "Warning"),
                    tb("Could not read who paused it or since when (parameter history unavailable).", isSubtle=True)]
    elif switch["state"] == "ON":
        body = [title_block("✅ SG monitoring is active: real-time alerts are ON.", "Good")]
        try:
            versions = switch_history()
            if versions:
                last = versions[-1]
                body.append(tb(f"Last switch change: {clean(actor_from_arn(last.get('LastModifiedUser')))} "
                               f"at {fmt_time(last.get('LastModifiedDate'))}", isSubtle=True))
        except Exception as e:
            log("switch_history_failed", error=str(e))
    else:
        body = [title_block(f"🔴 Alert switch is {switch['state']}", "Attention"),
                tb(f"Detail: {switch.get('detail', '')}. Alerts are being treated as ON (fail-safe). "
                   f"Recreate or fix the parameter {SWITCH_PARAM}.")]
    body.insert(1, tb(fmt_time(now_utc()), isSubtle=True))
    post_to_teams(body)
    return {"status": "posted", "switch": switch["state"]}


# --------------------------------------------------------------------------------------------
# Flow 2: real-time SG change (skipped while the switch is OFF)
# --------------------------------------------------------------------------------------------

def handle_sg_event(event):
    detail = event.get("detail") or {}
    name = detail.get("eventName")
    region = detail.get("awsRegion") or event.get("region")
    if detail.get("errorCode") or name not in SG_EVENTS or not region:
        return {"status": "ignored"}

    who = actor_from_identity(detail.get("userIdentity"))
    req_ids = extract_ids(detail.get("requestParameters"))
    all_ids = extract_ids(detail.get("responseElements"), extract_ids(detail.get("requestParameters")))
    summary = {"event": name, "region": region, "by": who, "event_time": detail.get("eventTime"),
               "ids": {k: sorted(v) for k, v in all_ids.items() if v}}

    switch = read_switch()
    if not switch["on"]:
        log("SKIPPED (maintenance)", **summary)
        return {"status": "skipped_maintenance"}

    # ModifyInstanceAttribute / ModifyNetworkInterfaceAttribute also cover unrelated attributes.
    if name in ATTACH_EVENTS and not req_ids["sg"]:
        return {"status": "ignored_not_sg_change"}

    inv = Inventory(region)
    target_sgs = set(all_ids["sg"])
    for iid in all_ids["i"]:
        target_sgs |= inv.groups_of_instance(iid)
    for eni in all_ids["eni"]:
        target_sgs |= inv.groups_of_eni(eni)
    for pl in all_ids["pl"]:
        target_sgs |= inv.groups_referencing_prefix_list(pl)
    if not target_sgs:
        log("no_security_groups_resolved", **summary)
        return {"status": "nothing_to_check"}

    findings = evaluate(inv, sorted(target_sgs))
    if name in RULE_EVENTS and all_ids["sgr"]:
        new = [f for f in findings if f["rule_id"] in all_ids["sgr"]]
    else:
        new = findings  # attachment / public-IP / prefix-list change: everything it touches is new exposure
    pre_existing = [f for f in findings if f not in new]
    log("sg_event_checked", new=len(new), pre_existing=len(pre_existing), **summary)
    if not new:
        return {"status": "no_exposure"}

    ident = detail.get("userIdentity") or {}
    mfa = (((ident.get("sessionContext") or {}).get("attributes") or {}).get("mfaAuthenticated"))
    crit = any(f["severity"] == "CRITICAL" for f in new)
    title = ("🔴 CRITICAL: sensitive port opened to the internet" if crit
             else "🟠 Port opened to the internet")
    body = [
        title_block(title, "Attention" if crit else "Warning"),
        facts([
            ("Changed by", clean(who)),
            ("Via", access_channel(detail)),
            ("MFA", {"true": "yes", "false": "NO"}.get(str(mfa).lower(), "")),
            ("Source IP", clean(detail.get("sourceIPAddress"), 60)),
            ("When", fmt_time(parse_iso(detail.get("eventTime")))),
            ("Action", f"{name} in {region}"),
        ]),
    ]
    banner = switch_banner(switch)
    if banner:
        body.append(tb(banner, color="Attention", weight="Bolder"))
    body += finding_blocks(new)
    if pre_existing:
        body.append(tb(f"Also already open on the same security group(s): {len(pre_existing)} finding(s). "
                       "They will appear in the 10:00 daily scan.", isSubtle=True))
    post_to_teams(body)
    return {"status": "alerted", "new": len(new)}


# --------------------------------------------------------------------------------------------
# Flow 4: switch changed (pause / resume / deleted)
# --------------------------------------------------------------------------------------------

def changes_during(start, end):
    """SG-related changes recorded in CloudTrail event history between start and end
    (free API, ~2 requests/second per region, events can take up to ~15 minutes to appear)."""
    changes, errors = [], []
    for region in MONITORED_REGIONS:
        ct = client("cloudtrail", region)
        for event_name in PAUSE_LOOKUP_EVENTS:
            try:
                pages = ct.get_paginator("lookup_events").paginate(
                    LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                    StartTime=start, EndTime=end + timedelta(minutes=1),
                    PaginationConfig={"MaxItems": 50},
                )
                for page in pages:
                    for ev in page.get("Events", []):
                        try:
                            record = json.loads(ev.get("CloudTrailEvent") or "{}")
                        except ValueError:
                            continue
                        if record.get("errorCode"):
                            continue
                        ids = extract_ids(record.get("requestParameters"))
                        if event_name in ATTACH_EVENTS and not ids["sg"]:
                            continue
                        refs = sorted(ids["sg"] | ids["i"] | ids["eni"] | ids["pl"])
                        changes.append({
                            "time": parse_iso(record.get("eventTime")) or ev.get("EventTime"),
                            "region": region,
                            "by": actor_from_identity(record.get("userIdentity")),
                            "action": event_name,
                            "resources": ", ".join(refs[:4]) + (" ..." if len(refs) > 4 else ""),
                        })
                    time.sleep(0.5)  # stay under the LookupEvents rate limit
            except ClientError as e:
                errors.append(f"{region}/{event_name}: {e.response.get('Error', {}).get('Code')}")
    changes.sort(key=lambda c: c["time"] or start)
    return changes, errors


def _resume_body(versions, findings, scan_errors, changes, change_errors):
    latest_idx = len(versions) - 1
    latest = versions[latest_idx]
    paused = pause_info(versions, latest_idx - 1)
    resumed_at = latest.get("LastModifiedDate")
    duration = fmt_duration(resumed_at - paused["at"]) if (resumed_at and paused["at"]) else "unknown"
    crit = any(f["severity"] == "CRITICAL" for f in findings)
    body = [
        title_block("▶️ SG alerts RESUMED", "Good"),
        facts([
            ("Resumed by", clean(actor_from_arn(latest.get("LastModifiedUser")))),
            ("Resumed at", fmt_time(resumed_at)),
            ("Paused by", clean(paused["by"])),
            ("Paused for", f"{duration} (since {fmt_time(paused['at'])})"),
            ("Pause reason", paused["reason"] or "no reason given"),
        ]),
        tb(f"**Changes made during the pause ({len(changes)})**", weight="Bolder"),
    ]
    for c in changes[:MAX_CHANGES_IN_CARD]:
        body.append(tb(f"{fmt_time(c['time'])} · {c['region']} · {clean(c['by'], 60)} · "
                       f"{c['action']} · {clean(c['resources'], 120)}", spacing="None"))
    if len(changes) > MAX_CHANGES_IN_CARD:
        body.append(tb(f"... and {len(changes) - MAX_CHANGES_IN_CARD} more (see CloudTrail).", isSubtle=True))
    if not changes:
        body.append(tb("None recorded.", spacing="None"))
    body.append(tb("CloudTrail can take up to ~15 minutes to show an event, so very recent changes may be "
                   "missing above. The catch-up scan below checks the live state.", isSubtle=True))
    if change_errors:
        body.append(tb("⚠️ Change history incomplete: " + "; ".join(change_errors[:5]), color="Warning"))
    body.append(tb("**Catch-up scan:** " + ("🔴 critical exposure found" if crit else
                                             f"{len(findings)} finding(s)" if findings else
                                             "⚠️ incomplete" if scan_errors else
                                             "✅ no critical ports open to the internet"),
                   weight="Bolder", color="Attention" if crit else "Default"))
    if scan_errors:
        body.append(tb("🔴 Could not scan: " + "; ".join(scan_errors), color="Attention"))
    body += finding_blocks(findings)
    return body


def handle_switch_change(event):
    operation = (event.get("detail") or {}).get("operation", "")
    if operation == "Delete":
        findings, errors = scan_all_regions()
        body = [
            title_block("🔴 Alert switch was DELETED", "Attention"),
            tb(f"{SWITCH_PARAM} no longer exists. Real-time alerts are forced ON (fail-safe). "
               "Recreate it with the setup command from the deployment guide. "
               f"Check CloudTrail (DeleteParameter in {HOME_REGION}) for who deleted it."),
            tb("**Catch-up scan:**", weight="Bolder"),
        ]
        if errors:
            body.append(tb("🔴 Could not scan: " + "; ".join(errors), color="Attention"))
        body += finding_blocks(findings) or ([] if errors else [tb("✅ no critical ports open to the internet")])
        post_to_teams(body)
        return {"status": "deleted_alerted"}

    if operation not in ("Create", "Update"):
        log("switch_event_ignored", operation=operation)
        return {"status": "ignored"}

    versions = switch_history()
    if not versions:
        return {"status": "no_history"}
    latest = versions[-1]
    new_value = latest.get("Value")
    old_value = versions[-2].get("Value") if len(versions) > 1 else None
    by = clean(actor_from_arn(latest.get("LastModifiedUser")))
    at = fmt_time(latest.get("LastModifiedDate"))

    if new_value == "OFF" and old_value != "OFF":
        info = pause_info(versions)
        body = [
            title_block("⏸️ SG alerts PAUSED (maintenance)", "Warning"),
            facts([
                ("Paused by", by),
                ("Paused at", at),
                ("Reason", info["reason"] or "no reason given"),
            ]),
            tb("Real-time SG alerts are OFF for all regions. The 10:00 daily scan still runs, and a "
               "reminder is posted at 07:00 and 19:00 until alerts are resumed."),
        ]
        post_to_teams(body)
        return {"status": "paused_posted"}

    if new_value == "ON" and old_value == "OFF":
        paused = pause_info(versions, len(versions) - 2)
        changes, change_errors = changes_during(paused["at"], latest.get("LastModifiedDate") or now_utc())
        findings, scan_errors = scan_all_regions()
        log("resume_catch_up", changes=len(changes), findings=len(findings),
            change_errors=change_errors, scan_errors=scan_errors)
        post_to_teams(_resume_body(versions, findings, scan_errors, changes, change_errors))
        return {"status": "resumed_posted"}

    if new_value not in ("ON", "OFF"):
        post_to_teams([title_block(f"🔴 Alert switch set to an invalid value by {by}", "Attention"),
                       tb(f"Value: {clean(new_value, 40)}. Alerts are treated as ON (fail-safe). "
                          "Set it to exactly ON or OFF.")])
        return {"status": "invalid_posted"}

    if operation == "Create":
        post_to_teams([title_block(f"ℹ️ Alert switch created by {by}", "Accent"),
                       tb(f"Initial value: {new_value} · {at}")])
        return {"status": "created_posted"}

    if new_value == "OFF":  # OFF re-saved, typically to update the reason
        reason = _fresh_reason(versions, len(versions) - 1)
        if reason:
            post_to_teams([title_block("⏸️ Maintenance pause updated", "Warning"),
                           facts([("Updated by", by), ("At", at), ("New reason", reason)])])
            return {"status": "pause_updated_posted"}
    log("switch_resaved_same_value", value=new_value, by=by)
    return {"status": "no_state_change"}


# --------------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------------

def lambda_handler(event, context):
    if not isinstance(event, dict):
        log("rejected_non_dict_event")
        return {"status": "ignored"}

    task = event.get("task")
    if task == "daily_scan":
        return run_daily_scan()
    if task == "switch_report":
        return run_switch_report()

    source, detail_type = event.get("source"), event.get("detail-type")
    if source == "aws.ec2" and detail_type == "AWS API Call via CloudTrail":
        return handle_sg_event(event)
    if source == "aws.ssm" and detail_type == "Parameter Store Change":
        name = ((event.get("detail") or {}).get("name") or "").lstrip("/")
        if name == SWITCH_PARAM.lstrip("/"):
            return handle_switch_change(event)

    log("rejected_unknown_event", source=source, detail_type=detail_type, keys=sorted(event)[:10])
    return {"status": "ignored"}
