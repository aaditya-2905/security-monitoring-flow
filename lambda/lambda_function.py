"""
SG Monitor - one Lambda that alerts Microsoft Teams about Security Group exposure.

Triggers (routed in lambda_handler):
  1. EventBridge Scheduler {"task": "daily_scan"}     10:00 IST full scan. Skipped while the switch is OFF.
                                                     Posts to Teams only when something is open.
  2. EventBridge rule, CloudTrail event (aws.ec2)      Real-time SG check. Skipped while the switch is OFF.
  3. EventBridge Scheduler {"task": "switch_check"}   07:00 / 19:00 IST. If the switch was left OFF (or is
                                                     missing / invalid), sets it back to ON and tells Teams.

Teams therefore only hears about two things: a port open to the internet, and the switch being
turned back ON because someone left it OFF.

The switch is the SSM parameter SWITCH_PARAM_NAME ("ON" / "OFF"). Anything other than an exact,
readable "OFF" is treated as ON (fail-safe), so a broken switch can never silence alerts.

Environment variables:
  TEAMS_WEBHOOK_URL       (required) Teams Workflows "webhook request received" URL.
  MONITORED_REGIONS       (required) Comma-separated regions for the daily scan.
  SWITCH_PARAM_NAME       default /secops/sg-monitor/notify-status
  CRITICAL_PORTS          optional override, e.g. "22:SSH,3389:RDP,6379" (name optional).
  ALLOWLIST               optional, e.g. "sg-0abc:443,sg-0abc:80,*:41641,sg-0def:8000-8100".
  ALERT_ANY_PUBLIC_PORT   "true" to also report non-critical ports open to the internet. Default false.
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
TZ =timezone(timedelta(minutes=int(os.environ.get("TZ_OFFSET_MINUTES", "330"))))
TZ_LABEL = os.environ.get("TZ_LABEL", "IST")

MAX_FINDINGS_IN_CARD = 25

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
    """Warning line for alert cards when the switch is broken (alerts are only sent while it counts
    as ON), or None when it is plainly ON."""
    if switch["state"] != "ON":
        return (f"🔴 Alert switch is {switch['state']} ({switch.get('detail', '')}). "
                "Treating it as ON (fail-safe). It is restored to ON at the next 07:00 / 19:00 check.")
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
# Flow 1: daily scan (10:00 IST) - skipped while the switch is OFF, posts only when something is open
# --------------------------------------------------------------------------------------------

def run_daily_scan():
    switch = read_switch()
    if not switch["on"]:
        log("SKIPPED (maintenance)", task="daily_scan")
        return {"status": "skipped_maintenance"}

    findings, errors = scan_all_regions()
    log("daily_scan", findings=len(findings), errors=errors, switch=switch["state"],
        details=findings)
    if not findings:
        if errors:
            # Nothing goes to Teams, so fail the invocation: the Lambda errors alarm emails the team.
            raise RuntimeError("Daily scan incomplete: " + "; ".join(errors))
        return {"status": "clean", "posted": False}

    crit = sum(f["severity"] == "CRITICAL" for f in findings)
    if crit:
        title, color = f"🛡️ Daily SG scan: {crit} CRITICAL exposure(s)", "Attention"
    else:
        title, color = f"🛡️ Daily SG scan: {len(findings)} open port finding(s)", "Warning"

    body = [title_block(title, color),
            tb(f"{fmt_time(now_utc())} · Regions: {', '.join(MONITORED_REGIONS)}", isSubtle=True)]
    banner = switch_banner(switch)
    if banner:
        body.append(tb(banner, color="Attention", weight="Bolder"))
    if errors:
        body.append(tb("🔴 Could not scan: " + "; ".join(errors) + ". Results for these regions are missing.",
                       color="Attention", weight="Bolder"))
    body += finding_blocks(findings)
    post_to_teams(body)
    return {"status": "posted", "findings": len(findings), "errors": errors}


# --------------------------------------------------------------------------------------------
# Flow 3: switch check (07:00 / 19:00 IST) - turns a switch left OFF back ON
# --------------------------------------------------------------------------------------------

def set_switch_on(previous_state):
    client("ssm").put_parameter(
        Name=SWITCH_PARAM, Value="ON", Type="String", Overwrite=True,
        AllowedPattern="^(ON|OFF)$",
        Description=f"Auto-reset to ON by sg-monitor (was {previous_state})",
    )


def run_switch_check():
    switch = read_switch()
    if switch["state"] == "ON":
        log("switch_check", state="ON")
        return {"status": "on"}
    if switch["state"] == "ERROR":
        # Unreadable (e.g. AccessDenied): don't overwrite blindly. Fail so the errors alarm emails the team.
        raise RuntimeError(f"Cannot read switch {SWITCH_PARAM}: {switch.get('detail')}")

    info = None
    if switch["state"] == "OFF":
        try:
            info = pause_info(switch_history())
        except Exception as e:
            log("switch_history_failed", error=str(e))
    set_switch_on(switch["state"])
    log("switch_reset", previous=switch["state"], pause=info)

    if switch["state"] == "OFF":
        if info:
            pause_facts = [
                ("Turned OFF by", clean(info["by"])),
                ("Turned OFF at", fmt_time(info["at"])),
                ("OFF for", fmt_duration(now_utc() - info["at"]) if info["at"] else ""),
                ("Reason", info["reason"] or "no reason given"),
            ]
        else:
            pause_facts = [("Turned OFF by", "unknown (parameter history unavailable)")]
        why = "The switch was left OFF after maintenance, so sg-monitor turned it back ON automatically."
    else:
        pause_facts = [("Switch was", f"{switch['state']} ({switch.get('detail', '')})")]
        why = "The switch parameter was missing or invalid, so sg-monitor restored it to ON."

    post_to_teams([
        title_block("🔄 SG monitoring switch turned back ON", "Warning"),
        tb(fmt_time(now_utc()), isSubtle=True),
        facts(pause_facts),
        tb(why + " Real-time SG alerts and the 10:00 daily scan are active again. "
           "If maintenance is still going on, turn alerts OFF again (SRE runbook)."),
    ])
    return {"status": "reset_posted", "previous": switch["state"]}


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
# Entry point
# --------------------------------------------------------------------------------------------

def lambda_handler(event, context):
    if not isinstance(event, dict):
        log("rejected_non_dict_event")
        return {"status": "ignored"}

    task = event.get("task")
    if task == "daily_scan":
        return run_daily_scan()
    if task == "switch_check":
        return run_switch_check()

    source, detail_type = event.get("source"), event.get("detail-type")
    if source == "aws.ec2" and detail_type == "AWS API Call via CloudTrail":
        return handle_sg_event(event)

    log("rejected_unknown_event", source=source, detail_type=detail_type, keys=sorted(event)[:10])
    return {"status": "ignored"}
