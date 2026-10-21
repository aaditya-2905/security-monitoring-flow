"""Offline tests for lambda_function.py. boto3/botocore are replaced with in-memory fakes, so no
AWS account or credentials are needed:  python3 -m unittest discover -s tests -v"""

import json
import os
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone

# ---- fake botocore / boto3 (installed before the module under test is imported) ----------

class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


botocore = types.ModuleType("botocore")
botocore_config = types.ModuleType("botocore.config")
botocore_config.Config = lambda **kw: kw
botocore_exceptions = types.ModuleType("botocore.exceptions")
botocore_exceptions.ClientError = ClientError
boto3 = types.ModuleType("boto3")
FAKES = {}
boto3.client = lambda service, region_name=None, config=None: FAKES[(service, region_name)]
sys.modules.update({"boto3": boto3, "botocore": botocore, "botocore.config": botocore_config,
                    "botocore.exceptions": botocore_exceptions})

os.environ.update({
    "AWS_REGION": "eu-west-2",
    "MONITORED_REGIONS": "eu-west-2,ap-south-1",
    "TEAMS_WEBHOOK_URL": "https://example.invalid/webhook",
    "ALLOWLIST": "sg-0a1b2c3d4e5f60001:443,*:41641",
})
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambda"))
import lambda_function as lf  # noqa: E402

lf.time.sleep = lambda s: None


class FakePaginator:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, **kwargs):
        yield self.fn(**kwargs)


class FakeEC2:
    def __init__(self, groups=None, rules=None, enis=None, instances=None, prefix_lists=None):
        self.groups = groups or []
        self.rules = rules or []
        self.enis = enis or []
        self.instances = instances or []
        self.prefix_lists = prefix_lists or {}

    @staticmethod
    def _filter(kwargs, name):
        for f in kwargs.get("Filters", []):
            if f["Name"] == name:
                return set(f["Values"])
        return None

    def get_paginator(self, op):
        def describe_security_group_rules(**kw):
            ids = self._filter(kw, "group-id")
            return {"SecurityGroupRules": [r for r in self.rules if ids is None or r["GroupId"] in ids]}

        def describe_security_groups(**kw):
            ids = self._filter(kw, "group-id")
            pl = self._filter(kw, "ip-permission.prefix-list-id")
            out = []
            for g in self.groups:
                if ids is not None and g["GroupId"] not in ids:
                    continue
                if pl is not None and not any(r["GroupId"] == g["GroupId"] and r.get("PrefixListId") in pl
                                              for r in self.rules):
                    continue
                out.append(g)
            return {"SecurityGroups": out}

        def describe_network_interfaces(**kw):
            return {"NetworkInterfaces": self.enis}

        def describe_instances(**kw):
            return {"Reservations": [{"Instances": self.instances}]}

        def get_managed_prefix_list_entries(PrefixListId, **kw):
            return {"Entries": [{"Cidr": c} for c in self.prefix_lists.get(PrefixListId, [])]}

        return FakePaginator(locals()[op])


class FakeSSM:
    def __init__(self, versions=None, missing=False, read_error=None, put_error=None):
        self.versions = versions or []
        self.missing = missing
        self.read_error = read_error
        self.put_error = put_error
        self.puts = []

    def get_parameter(self, Name):
        if self.read_error:
            raise ClientError(self.read_error)
        if self.missing or not self.versions:
            raise ClientError("ParameterNotFound")
        return {"Parameter": {"Value": self.versions[-1]["Value"]}}

    def put_parameter(self, **kw):
        if self.put_error:
            raise ClientError(self.put_error)
        self.puts.append(kw)

    def get_parameter_history(self, Name, MaxResults=50, NextToken=None):
        start = int(NextToken or 0)
        page = self.versions[start:start + MaxResults]
        resp = {"Parameters": page}
        if start + MaxResults < len(self.versions):
            resp["NextToken"] = str(start + MaxResults)
        return resp


# ---- fixtures ------------------------------------------------------------------------------

T0 = datetime(2026, 10, 21, 8, 50, tzinfo=timezone.utc)  # 14:20 IST
SG_WEB, SG_DB = "sg-0a1b2c3d4e5f60001", "sg-0a1b2c3d4e5f60002"
USER = "arn:aws:iam::123456789012:user/"


def version(n, value, user, minutes, desc=""):
    return {"Version": n, "Value": value, "LastModifiedUser": USER + user,
            "LastModifiedDate": T0 + timedelta(minutes=minutes), "Description": desc}


def world_ec2():
    return FakeEC2(
        groups=[{"GroupId": SG_WEB, "GroupName": "web-alb"}, {"GroupId": SG_DB, "GroupName": "db"}],
        rules=[
            {"SecurityGroupRuleId": "sgr-00000000000000001", "GroupId": SG_WEB, "IsEgress": False,
             "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIpv4": "0.0.0.0/0"},
            {"SecurityGroupRuleId": "sgr-00000000000000002", "GroupId": SG_DB, "IsEgress": False,
             "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306, "CidrIpv4": "0.0.0.0/0",
             "Description": "temp [click](http://evil.example)"},
            {"SecurityGroupRuleId": "sgr-00000000000000003", "GroupId": SG_DB, "IsEgress": False,
             "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv4": "10.0.0.0/16"},
            {"SecurityGroupRuleId": "sgr-00000000000000004", "GroupId": SG_DB, "IsEgress": True,
             "IpProtocol": "-1", "CidrIpv4": "0.0.0.0/0"},
        ],
        enis=[{"NetworkInterfaceId": "eni-00000000000000001", "PrivateIpAddress": "10.0.1.5",
               "Attachment": {"InstanceId": "i-00000000000000001"},
               "Association": {"PublicIp": "3.8.1.2"}, "Groups": [{"GroupId": SG_DB}]}],
        instances=[{"InstanceId": "i-00000000000000001", "Tags": [{"Key": "Name", "Value": "api-prod-02"}]}],
    )


def cloudtrail_event(name, request, response=None, user="jdoe", error=None):
    detail = {"eventName": name, "awsRegion": "eu-west-2", "eventTime": "2026-10-21T09:00:00Z",
              "userIdentity": {"type": "IAMUser", "userName": user, "arn": USER + user,
                               "sessionContext": {"attributes": {"mfaAuthenticated": "true"}}},
              "sourceIPAddress": "203.0.113.9", "userAgent": "aws-cli/2.17",
              "requestParameters": request, "responseElements": response}
    if error:
        detail["errorCode"] = error
    return {"source": "aws.ec2", "detail-type": "AWS API Call via CloudTrail", "detail": detail}


def card_text(body):
    return json.dumps(body, ensure_ascii=False)


class Base(unittest.TestCase):
    def setUp(self):
        lf._clients.clear()
        FAKES.clear()
        self.posts = []
        lf.post_to_teams = self.posts.append
        FAKES[("ec2", "eu-west-2")] = world_ec2()
        FAKES[("ec2", "ap-south-1")] = FakeEC2()
        FAKES[("ssm", "eu-west-2")] = FakeSSM([version(1, "ON", "admin", -600, "Initial setup")])


# ---- pure helpers --------------------------------------------------------------------------

class HelperTests(unittest.TestCase):
    def test_is_world(self):
        for cidr in ("0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "3.0.0.0/8", "::/0", "2000::/3"):
            self.assertTrue(lf.is_world(cidr), cidr)
        for cidr in ("10.0.0.0/8", "1.2.3.4/32", "100.64.0.0/10", "172.16.0.0/12", "fc00::/7", "bad"):
            self.assertFalse(lf.is_world(cidr), cidr)

    def test_actor_parsing(self):
        self.assertEqual(lf.actor_from_arn(USER + "jdoe"), "jdoe")
        self.assertEqual(lf.actor_from_arn("arn:aws:iam::1:user/ops/team/rahul"), "rahul")
        self.assertEqual(lf.actor_from_arn("arn:aws:iam::1:root"), "ROOT ACCOUNT")
        self.assertEqual(lf.actor_from_arn("arn:aws:sts::1:assumed-role/CI/run-42"), "run-42 (role CI)")

    def test_clean_neutralises_markdown_and_links(self):
        out = lf.clean("[Fix now](https://evil.example) **x** www.evil.example")
        self.assertNotIn("](", out)
        self.assertNotIn("https://", out)
        self.assertNotIn("**", out)
        self.assertIn("www[.]", out)

    def test_extract_ids(self):
        ids = lf.extract_ids({"a": [{"groupId": SG_DB}, {"x": "sgr-00000000000000002"}], "i": "i-00000000000000001"})
        self.assertEqual(ids["sg"], {SG_DB})
        self.assertEqual(ids["sgr"], {"sgr-00000000000000002"})
        self.assertEqual(ids["i"], {"i-00000000000000001"})

    def test_duration(self):
        self.assertEqual(lf.fmt_duration(timedelta(hours=26, minutes=5)), "1d 2h 5m")
        self.assertEqual(lf.fmt_duration(timedelta(minutes=195)), "3h 15m")


# ---- evaluation ----------------------------------------------------------------------------

class EvaluateTests(Base):
    def test_critical_public_db_port_and_allowlisted_443(self):
        findings = lf.evaluate(lf.Inventory("eu-west-2"))
        self.assertEqual(len(findings), 1)  # 443 allowlisted, 22 is internal, egress ignored
        f = findings[0]
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(f["critical"], ["3306 (MySQL)"])
        self.assertEqual(f["resources"][0]["name"], "api-prod-02")

    def test_all_traffic_rule_lists_every_critical_port_and_no_public_ip_is_high(self):
        ec2 = FakeEC2(groups=[{"GroupId": SG_DB, "GroupName": "db"}],
                      rules=[{"SecurityGroupRuleId": "sgr-00000000000000009", "GroupId": SG_DB,
                              "IpProtocol": "-1", "CidrIpv6": "::/0"}])
        FAKES[("ec2", "eu-west-2")] = ec2
        f = lf.evaluate(lf.Inventory("eu-west-2"))[0]
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["exposure"], "Not attached to any server yet")
        self.assertIn("22 (SSH)", f["critical"])
        self.assertEqual(f["ports"], "all ports")

    def test_prefix_list_containing_world(self):
        ec2 = world_ec2()
        ec2.rules = [{"SecurityGroupRuleId": "sgr-00000000000000010", "GroupId": SG_DB,
                      "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "PrefixListId": "pl-00000000000000001"}]
        ec2.prefix_lists = {"pl-00000000000000001": ["198.51.100.0/24", "0.0.0.0/0"]}
        FAKES[("ec2", "eu-west-2")] = ec2
        f = lf.evaluate(lf.Inventory("eu-west-2"))[0]
        self.assertIn("via prefix list", f["source"])
        self.assertEqual(f["severity"], "CRITICAL")


# ---- switch --------------------------------------------------------------------------------

class SwitchTests(Base):
    def test_fail_safe(self):
        FAKES[("ssm", "eu-west-2")] = FakeSSM(missing=True)
        self.assertEqual(lf.read_switch(), {"state": "MISSING", "on": True, "detail": "ParameterNotFound"})
        FAKES[("ssm", "eu-west-2")] = FakeSSM([version(1, "off", "x", 0)])
        lf._clients.clear()
        self.assertTrue(lf.read_switch()["on"])

    def test_pause_info_uses_start_of_streak_and_latest_fresh_reason(self):
        versions = [version(1, "ON", "admin", -600, "Initial setup"),
                    version(2, "OFF", "rahul", 0, "CHG-1 patching"),
                    version(3, "OFF", "priya", 30, "CHG-1 patching"),       # re-saved, same reason
                    version(4, "OFF", "priya", 60, "CHG-1 patching + reboot")]
        info = lf.pause_info(versions)
        self.assertEqual(info["by"], "rahul")
        self.assertEqual(info["at"], T0)
        self.assertEqual(info["reason"], "CHG-1 patching + reboot")

    def test_history_pagination(self):
        versions = [version(i, "ON" if i % 2 else "OFF", "u", i) for i in range(1, 121)]
        FAKES[("ssm", "eu-west-2")] = FakeSSM(versions)
        self.assertEqual(len(lf.switch_history()), 120)


# ---- end-to-end flows ----------------------------------------------------------------------

class FlowTests(Base):
    def test_daily_scan_posts_findings(self):
        out = lf.lambda_handler({"task": "daily_scan"}, None)
        self.assertEqual(out["findings"], 1)
        text = card_text(self.posts[0])
        self.assertIn("CRITICAL", text)
        self.assertNotIn("http://evil", text)

    def test_daily_scan_skipped_when_switch_off(self):
        FAKES[("ssm", "eu-west-2")] = FakeSSM([version(1, "OFF", "rahul", 0, "CHG-1")])
        del FAKES[("ec2", "eu-west-2")]  # any scan attempt would now fail
        self.assertEqual(lf.lambda_handler({"task": "daily_scan"}, None)["status"], "skipped_maintenance")
        self.assertEqual(self.posts, [])

    def test_daily_scan_clean_posts_nothing(self):
        FAKES[("ec2", "eu-west-2")] = FakeEC2()
        self.assertEqual(lf.lambda_handler({"task": "daily_scan"}, None)["status"], "clean")
        self.assertEqual(self.posts, [])

    def test_daily_scan_reports_region_failure(self):
        class Broken(FakeEC2):
            def get_paginator(self, op):
                raise ClientError("UnauthorizedOperation")
        FAKES[("ec2", "ap-south-1")] = Broken()
        out = lf.lambda_handler({"task": "daily_scan"}, None)
        self.assertEqual(out["errors"], ["ap-south-1: UnauthorizedOperation"])
        self.assertIn("Could not scan", card_text(self.posts[0]))

    def test_daily_scan_with_errors_and_no_findings_fails_without_posting(self):
        class Broken(FakeEC2):
            def get_paginator(self, op):
                raise ClientError("UnauthorizedOperation")
        FAKES[("ec2", "eu-west-2")] = FakeEC2()
        FAKES[("ec2", "ap-south-1")] = Broken()
        with self.assertRaises(RuntimeError):
            lf.lambda_handler({"task": "daily_scan"}, None)
        self.assertEqual(self.posts, [])

    def test_switch_check_on_does_nothing(self):
        ssm = FAKES[("ssm", "eu-west-2")]
        self.assertEqual(lf.lambda_handler({"task": "switch_check"}, None)["status"], "on")
        self.assertEqual(ssm.puts, [])
        self.assertEqual(self.posts, [])

    def test_switch_check_turns_off_back_on_and_posts(self):
        ssm = FakeSSM([version(1, "ON", "admin", -600),
                       version(2, "OFF", "rahul", 0, "CHG-1234 DB patching")])
        FAKES[("ssm", "eu-west-2")] = ssm
        lf.now_utc = lambda: T0 + timedelta(hours=16, minutes=40)
        try:
            out = lf.lambda_handler({"task": "switch_check"}, None)
        finally:
            lf.now_utc = lambda: datetime.now(timezone.utc)
        self.assertEqual(out["status"], "reset_posted")
        self.assertEqual(ssm.puts[0]["Value"], "ON")
        self.assertTrue(ssm.puts[0]["Overwrite"])
        text = card_text(self.posts[0])
        self.assertIn("turned back ON", text)
        self.assertIn("rahul", text)
        self.assertIn("16h 40m", text)
        self.assertIn("CHG-1234 DB patching", text)

    def test_switch_check_restores_missing_switch(self):
        ssm = FakeSSM(missing=True)
        FAKES[("ssm", "eu-west-2")] = ssm
        self.assertEqual(lf.lambda_handler({"task": "switch_check"}, None)["previous"], "MISSING")
        self.assertEqual(ssm.puts[0]["Value"], "ON")
        self.assertIn("MISSING", card_text(self.posts[0]))

    def test_switch_check_unreadable_switch_fails_without_writing(self):
        ssm = FakeSSM(read_error="AccessDeniedException")
        FAKES[("ssm", "eu-west-2")] = ssm
        with self.assertRaises(RuntimeError):
            lf.lambda_handler({"task": "switch_check"}, None)
        self.assertEqual(ssm.puts, [])
        self.assertEqual(self.posts, [])

    def test_switch_check_reset_failure_does_not_post(self):
        FAKES[("ssm", "eu-west-2")] = FakeSSM([version(1, "OFF", "rahul", 0)], put_error="AccessDeniedException")
        with self.assertRaises(ClientError):
            lf.lambda_handler({"task": "switch_check"}, None)
        self.assertEqual(self.posts, [])

    def test_sg_event_alerts_new_critical_rule(self):
        ev = cloudtrail_event("AuthorizeSecurityGroupIngress", {"groupId": SG_DB},
                              {"securityGroupRuleSet": {"items": [{"securityGroupRuleId": "sgr-00000000000000002"}]}})
        out = lf.lambda_handler(ev, None)
        self.assertEqual(out, {"status": "alerted", "new": 1})
        text = card_text(self.posts[0])
        self.assertIn("jdoe", text)
        self.assertIn("3306 (MySQL)", text)
        self.assertIn("api-prod-02", text)

    def test_sg_event_safe_rule_does_not_alert(self):
        ev = cloudtrail_event("AuthorizeSecurityGroupIngress", {"groupId": SG_DB},
                              {"securityGroupRuleSet": {"items": [{"securityGroupRuleId": "sgr-00000000000000003"}]}})
        self.assertEqual(lf.lambda_handler(ev, None)["status"], "no_exposure")
        self.assertEqual(self.posts, [])

    def test_sg_event_skipped_when_switch_off(self):
        FAKES[("ssm", "eu-west-2")] = FakeSSM([version(1, "OFF", "rahul", 0)])
        ev = cloudtrail_event("AuthorizeSecurityGroupIngress", {"groupId": SG_DB},
                              {"securityGroupRuleSet": {"items": [{"securityGroupRuleId": "sgr-00000000000000002"}]}})
        self.assertEqual(lf.lambda_handler(ev, None)["status"], "skipped_maintenance")
        self.assertEqual(self.posts, [])

    def test_sg_event_checked_with_warning_when_switch_missing(self):
        FAKES[("ssm", "eu-west-2")] = FakeSSM(missing=True)
        ev = cloudtrail_event("AuthorizeSecurityGroupIngress", {"groupId": SG_DB},
                              {"securityGroupRuleSet": {"items": [{"securityGroupRuleId": "sgr-00000000000000002"}]}})
        self.assertEqual(lf.lambda_handler(ev, None)["status"], "alerted")
        self.assertIn("MISSING", card_text(self.posts[0]))

    def test_failed_api_call_ignored(self):
        ev = cloudtrail_event("AuthorizeSecurityGroupIngress", {"groupId": SG_DB}, error="UnauthorizedOperation")
        self.assertEqual(lf.lambda_handler(ev, None)["status"], "ignored")

    def test_attach_open_sg_to_instance_alerts(self):
        ev = cloudtrail_event("ModifyInstanceAttribute",
                              {"instanceId": "i-00000000000000001", "groupSet": {"items": [{"groupId": SG_DB}]}})
        self.assertEqual(lf.lambda_handler(ev, None)["status"], "alerted")

    def test_unrelated_instance_attribute_change_ignored(self):
        ev = cloudtrail_event("ModifyInstanceAttribute", {"instanceId": "i-00000000000000001",
                                                          "instanceType": {"value": "t3.large"}})
        self.assertEqual(lf.lambda_handler(ev, None)["status"], "ignored_not_sg_change")

    def test_public_ip_associated_alerts(self):
        ev = cloudtrail_event("AssociateAddress", {"instanceId": "i-00000000000000001",
                                                   "allocationId": "eipalloc-1"})
        self.assertEqual(lf.lambda_handler(ev, None)["status"], "alerted")

    def test_unknown_event_rejected(self):
        self.assertEqual(lf.lambda_handler({"source": "custom.attacker"}, None)["status"], "ignored")
        # Switch changes no longer trigger anything: the SG events themselves are what get checked.
        self.assertEqual(lf.lambda_handler({"source": "aws.ssm", "detail-type": "Parameter Store Change",
                                            "detail": {"operation": "Update",
                                                       "name": "/secops/sg-monitor/notify-status"}},
                                           None)["status"], "ignored")
        self.assertEqual(self.posts, [])


class TeamsPostTests(unittest.TestCase):
    def test_rejects_non_https_url(self):
        post = lf.__dict__.get("_real_post")
        os.environ["TEAMS_WEBHOOK_URL"] = "http://insecure"
        try:
            with self.assertRaises(RuntimeError):
                post([])
        finally:
            os.environ["TEAMS_WEBHOOK_URL"] = "https://example.invalid/webhook"


lf._real_post = lf.post_to_teams

if __name__ == "__main__":
    unittest.main()
