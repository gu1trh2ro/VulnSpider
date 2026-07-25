from __future__ import annotations
import ipaddress,re
from collections import Counter
from urllib.parse import urlparse
from .models import Candidate,PayloadItem,RejectedPayload,ValidationResult,VerificationGroup,VulnerabilityType

SQL_BLOCK=[
("stacked query",re.compile(r";")),("SQL comment",re.compile(r"(--|#|/\*)")),
("time delay",re.compile(r"\b(sleep|benchmark|pg_sleep|waitfor)\b",re.I)),
("extraction",re.compile(r"\b(union|select|information_schema|load_file)\b",re.I)),
("modification",re.compile(r"\b(insert|update|delete|drop|alter|truncate|create|replace|merge)\b",re.I)),
]
XSS_BLOCK=[
("script",re.compile(r"<\s*/?\s*script\b",re.I)),("event handler",re.compile(r"\bon[a-z]+\s*=",re.I)),
("active scheme",re.compile(r"\b(javascript|vbscript|data)\s*:",re.I)),
("active element",re.compile(r"<\s*(iframe|object|embed|svg|math)\b",re.I)),
("external URL",re.compile(r"https?://",re.I)),
("browser secret access",re.compile(r"\b(document\.cookie|localStorage|sessionStorage)\b",re.I)),
]
STATE_PATH=re.compile(r"/(delete|remove|destroy|purchase|checkout|transfer|withdraw)(/|$)",re.I)

class PayloadValidator:
    def __init__(self,allowed_hosts=None,allowed_ports=None,max_payload_length=200):
        self.allowed_hosts=allowed_hosts or {"localhost","127.0.0.1","::1"}
        self.allowed_ports=allowed_ports or {3000,8899}
        self.max_payload_length=max_payload_length

    def _url(self,url):
        p=urlparse(url); out=[]
        if p.scheme not in {"http","https"}: out.append("scheme must be http/https")
        if p.username or p.password: out.append("userinfo in URL is blocked")
        if p.fragment: out.append("URL fragment is blocked")
        host=p.hostname
        try: loopback=host in self.allowed_hosts or ipaddress.ip_address(host).is_loopback
        except Exception: loopback=host in self.allowed_hosts
        if not loopback: out.append("host outside loopback allowlist")
        port=p.port or (443 if p.scheme=="https" else 80)
        if port not in self.allowed_ports: out.append(f"port {port} not allowed")
        if STATE_PATH.search(p.path): out.append("state-changing path blocked")
        return out

    def _common(self,c,p):
        out=[]
        if p.destructive: out.append("destructive=true")
        if not p.payload.strip(): out.append("empty payload")
        if len(p.payload)>self.max_payload_length: out.append("payload too long")
        if c.request_context.method not in {"GET","POST"}: out.append("method blocked")
        if c.vulnerability_type==VulnerabilityType.BAC and c.request_context.method!="GET": out.append("BAC permits GET only")
        return out

    def validate(self,candidate,group):
        global_r=self._url(str(candidate.request_context.url))
        if group.candidate_id!=candidate.candidate_id: global_r.append("candidate_id mismatch")
        if group.target.parameter_name!=candidate.request_context.parameter_name: global_r.append("target mismatch")
        if candidate.request_context.parameter_location not in {"query","body"}: global_r.append("only query/body supported")
        if len(group.payloads) not in {3,4}: global_r.append("payload count must be 3 or 4")

        allowed=[]; rejected=[]
        resources={r.value for r in candidate.resources}
        contexts={a.context_id for a in candidate.auth_contexts}
        for item in group.payloads:
            reasons=list(global_r)+self._common(candidate,item)
            if candidate.vulnerability_type==VulnerabilityType.SQLI:
                if item.payload_role not in {"true_condition","false_condition"}: reasons.append("invalid SQLI role")
                for name,pat in SQL_BLOCK:
                    if pat.search(item.payload): reasons.append(name)
            elif candidate.vulnerability_type==VulnerabilityType.XSS:
                if item.payload_role not in {"control","reflection_marker"}: reasons.append("invalid XSS role")
                if item.payload_role=="reflection_marker" and "xss-probe" not in item.payload.lower(): reasons.append("missing xss-probe")
                for name,pat in XSS_BLOCK:
                    if pat.search(item.payload): reasons.append(name)
            else:
                if len(resources)<2 or len(contexts)<2: reasons.append("BAC needs >=2 resources and auth contexts")
                if item.payload not in resources: reasons.append("resource outside allowlist")
                if item.auth_context_id not in contexts: reasons.append("auth context outside allowlist")
                if item.payload_role not in {"authorization_control","authorization_variant"}: reasons.append("invalid BAC role")
            if reasons: rejected.append(RejectedPayload(payload_id=item.payload_id,payload=item.payload,reasons=sorted(set(reasons))))
            else: allowed.append(item)

        roles=Counter(x.payload_role for x in allowed)
        shape=(
            candidate.vulnerability_type==VulnerabilityType.SQLI and len(allowed)==4 and roles["true_condition"]==2 and roles["false_condition"]==2
        ) or (
            candidate.vulnerability_type==VulnerabilityType.XSS and len(allowed)==3 and roles["control"]==1 and roles["reflection_marker"]==2
        ) or (
            candidate.vulnerability_type==VulnerabilityType.BAC and len(allowed)==4 and roles["authorization_control"]==1 and roles["authorization_variant"]==3
        )
        return ValidationResult(
            verification_group_id=group.verification_group_id,candidate_id=candidate.candidate_id,
            allowed_payloads=allowed,rejected_payloads=rejected,executable=(not rejected and shape)
        )
