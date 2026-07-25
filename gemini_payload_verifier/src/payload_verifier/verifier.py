from __future__ import annotations
import asyncio,hashlib,html,re,statistics,uuid
from collections import defaultdict
from html.parser import HTMLParser
from urllib.parse import parse_qsl,urlencode,urlsplit,urlunsplit
import httpx
from .models import Candidate,PayloadItem,RequestResult,ValidationResult,VerificationObservations,VerificationRecord,VulnerabilityType

SQL_ERROR_RE=re.compile(r"(sql syntax|mysql_fetch|mysqli|postgresql.*error|unterminated quoted string|sqlite.*error|ora-\d{5}|odbc sql|syntax error at or near)",re.I)
DENIAL_RE=re.compile(r"\b(forbidden|unauthorized|access denied|permission denied|not allowed|login required)\b",re.I)
URL_ATTRS={"href","src","action","formaction","poster"}

class MarkerParser(HTMLParser):
    def __init__(self,marker):
        super().__init__(convert_charrefs=False); self.marker=marker; self.stack=[]; self.contexts=set(); self.dangerous=set()
    def handle_starttag(self,tag,attrs):
        self.stack.append(tag.lower())
        for name,value in attrs:
            if value is None or self.marker not in value: continue
            n=name.lower(); self.contexts.add(f"attribute:{n}")
            if n.startswith("on"): self.dangerous.add("event_handler_attribute")
            elif n in URL_ATTRS: self.dangerous.add("url_attribute")
            elif n=="style": self.dangerous.add("css_attribute")
            elif n=="srcdoc": self.dangerous.add("srcdoc_attribute")
            elif any(ch in value for ch in ['"',"'","<",">"]): self.dangerous.add("attribute_breakout_candidate")
    def handle_startendtag(self,tag,attrs):
        self.handle_starttag(tag,attrs)
        if self.stack: self.stack.pop()
    def handle_endtag(self,tag):
        tag=tag.lower()
        while self.stack:
            if self.stack.pop()==tag: break
    def handle_data(self,data):
        if self.marker not in data: return
        parent=self.stack[-1] if self.stack else ""
        if parent=="script": self.contexts.add("javascript_text"); self.dangerous.add("javascript_string_or_code")
        elif parent=="style": self.contexts.add("css_text"); self.dangerous.add("css_context")
        else:
            self.contexts.add("html_text")
            if any(ch in data for ch in "<>"): self.dangerous.add("html_markup_candidate")
    def handle_comment(self,data):
        if self.marker in data: self.contexts.add("html_comment"); self.dangerous.add("comment_breakout_candidate")

def analyze_context(body,marker):
    p=MarkerParser(marker)
    try: p.feed(body)
    except Exception: pass
    esc=re.escape(marker)
    if re.search(rf"<script\b[^>]*>[\s\S]*?{esc}[\s\S]*?</script>",body,re.I):
        p.contexts.add("javascript_text"); p.dangerous.add("javascript_string_or_code")
    if re.search(rf"<style\b[^>]*>[\s\S]*?{esc}[\s\S]*?</style>",body,re.I):
        p.contexts.add("css_text"); p.dangerous.add("css_context")
    return sorted(p.contexts),sorted(p.dangerous)

def sha(text): return hashlib.sha256(text.encode("utf-8",errors="replace")).hexdigest()

def normalize_response_body(text, payload):
    """
    비교를 방해하는 요청별 반사값과 흔한 동적 값을 제거한다.
    payload가 에러 페이지에 그대로 출력되어 각 응답 해시가 달라지는 오탐을 방지한다.
    """
    normalized = text
    if payload:
        normalized = normalized.replace(payload, "<PAYLOAD>")
        normalized = normalized.replace(html.escape(payload, quote=True), "<PAYLOAD>")
    normalized = re.sub(r"\b[0-9a-f]{32,64}\b", "<HEX>", normalized, flags=re.I)
    normalized = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-Z]+\b", "<TIMESTAMP>", normalized)
    normalized = re.sub(r"\brequest[-_ ]?id\s*[:=]\s*[\w-]+", "request_id=<ID>", normalized, flags=re.I)
    return normalized
def diff(a,b): return abs(a-b)/max(a,b,1.0)
def replace_query(url,name,occ,value):
    parts=urlsplit(url); pairs=parse_qsl(parts.query,keep_blank_values=True); out=[]; seen=0; done=False
    for k,v in pairs:
        if k==name:
            if seen==occ: out.append((k,value)); done=True
            else: out.append((k,v))
            seen+=1
        else: out.append((k,v))
    if not done: out.append((name,value))
    return urlunsplit((parts.scheme,parts.netloc,parts.path,urlencode(out),parts.fragment))

def empty_obs():
    return VerificationObservations(status_code_difference=False,response_length_difference_ratio=0.0,
        elapsed_time_difference_ratio=0.0,body_fingerprint_difference=False,sql_error_pattern=False,
        repeatable=False,successful_requests=0,total_requests=0)

class FocusedVerifier:
    def __init__(self,timeout_seconds=5.0,repeats=1,max_response_bytes=1_000_000):
        self.timeout_seconds=timeout_seconds; self.repeats=repeats; self.max_response_bytes=max_response_bytes

    def _auth(self,candidate,item):
        return next((x for x in candidate.auth_contexts if x.context_id==item.auth_context_id),None)

    async def _send(self,client,candidate,item):
        ctx=candidate.request_context; url=str(ctx.url); headers=dict(ctx.headers); auth=self._auth(candidate,item)
        if auth: headers.update(auth.headers)
        kwargs={"headers":headers}
        if ctx.parameter_location=="query": url=replace_query(url,ctx.parameter_name,ctx.parameter_occurrence,item.payload)
        elif ctx.parameter_location=="body":
            body=dict(ctx.body or {}); body[ctx.parameter_name]=item.payload
            kwargs["json" if ctx.content_type=="json" else "data"]=body
        else:
            return RequestResult(payload_id=item.payload_id,payload_role=item.payload_role,payload=item.payload,
                auth_context_id=item.auth_context_id,expected_access=item.expected_access,status_code=None,
                response_length=None,elapsed_ms=None,body_sha256=None,execution_error="unsupported location")
        try:
            r=await client.request(ctx.method,url,**kwargs); raw=r.content[:self.max_response_bytes]
            text=raw.decode(r.encoding or "utf-8",errors="replace")
            reflected=item.payload in text
            escaped=html.escape(item.payload,quote=True) in text and not reflected
            contexts,dangerous=analyze_context(text,item.payload) if candidate.vulnerability_type==VulnerabilityType.XSS and reflected else ([],[])
            granted=200<=r.status_code<300 and not DENIAL_RE.search(text) and len(raw)>0
            return RequestResult(payload_id=item.payload_id,payload_role=item.payload_role,payload=item.payload,
                auth_context_id=item.auth_context_id,auth_role=auth.role if auth else None,
                principal_id=auth.principal_id if auth else None,expected_access=item.expected_access,
                status_code=r.status_code,response_length=len(raw),elapsed_ms=round(r.elapsed.total_seconds()*1000,3),
                body_sha256=sha(text),normalized_body_sha256=sha(normalize_response_body(text,item.payload)),content_type=r.headers.get("content-type"),
                sql_error_pattern=bool(SQL_ERROR_RE.search(text)),reflected=reflected,
                escaped_reflection=escaped,reflection_contexts=contexts,dangerous_contexts=dangerous,
                access_granted=granted,execution_error=None)
        except Exception as e:
            return RequestResult(payload_id=item.payload_id,payload_role=item.payload_role,payload=item.payload,
                auth_context_id=item.auth_context_id,auth_role=auth.role if auth else None,
                principal_id=auth.principal_id if auth else None,expected_access=item.expected_access,
                status_code=None,response_length=None,elapsed_ms=None,body_sha256=None,
                execution_error=f"{type(e).__name__}: {e}")

    async def _execute(self,candidate,validation):
        out=[]
        async with httpx.AsyncClient(timeout=httpx.Timeout(self.timeout_seconds),follow_redirects=False,trust_env=False) as client:
            for _ in range(self.repeats):
                for item in validation.allowed_payloads:
                    out.append(await self._send(client,candidate,item)); await asyncio.sleep(.15)
        return out

    def _stable(self,items,needed=None):
        needed=needed or self.repeats
        if len(items)<needed: return False
        statuses={x.status_code for x in items}; lengths=[x.response_length or 0 for x in items]
        return len(statuses)==1 and max(lengths)-min(lengths)<=max(int(max(lengths,default=0)*.05),20)

    def _median(self,items,attr):
        vals=[getattr(x,attr) for x in items if getattr(x,attr) is not None]
        return float(statistics.median(vals)) if vals else 0.0

    def _compare(self,a,b):
        return (
            {x.status_code for x in a if x.status_code is not None}!={x.status_code for x in b if x.status_code is not None},
            diff(self._median(a,"response_length"),self._median(b,"response_length")),
            diff(self._median(a,"elapsed_ms"),self._median(b,"elapsed_ms")),
            {x.normalized_body_sha256 for x in a if x.normalized_body_sha256}!={x.normalized_body_sha256 for x in b if x.normalized_body_sha256}
        )

    def _record(self,c,t,results,obs,verdict,reason):
        return VerificationRecord(verification_id=f"verify_{uuid.uuid4().hex[:12]}",candidate_id=c.candidate_id,
            vulnerability_type=c.vulnerability_type,verification_type=t,request_results=results,
            observations=obs,verification_result=verdict,reason=reason)

    def _sqli(self,c,results):
        ok=[r for r in results if r.execution_error is None]
        by_role=defaultdict(list)
        by_payload=defaultdict(list)
        for r in ok:
            by_role[r.payload_role].append(r)
            by_payload[r.payload_id].append(r)

        trues=by_role["true_condition"]
        falses=by_role["false_condition"]
        sd,lr,er,bd=self._compare(trues,falses)

        # 각 개별 payload가 반복 실행에서 안정적인지 확인한다.
        per_payload_repeatable=bool(by_payload) and all(
            self._stable(items,self.repeats) for items in by_payload.values()
        )

        # 같은 역할 안의 서로 다른 payload도 정규화 응답이 서로 일관적인지 확인한다.
        true_fingerprints={r.normalized_body_sha256 for r in trues if r.normalized_body_sha256}
        false_fingerprints={r.normalized_body_sha256 for r in falses if r.normalized_body_sha256}
        true_group_consistent=len(true_fingerprints)==1
        false_group_consistent=len(false_fingerprints)==1
        repeat=per_payload_repeatable and true_group_consistent and false_group_consistent

        sql_error_count=sum(1 for r in ok if r.sql_error_pattern)
        all_sql_errors=bool(ok) and sql_error_count==len(ok)
        boolean_difference=sd or lr>=.20 or bd

        obs=VerificationObservations(
            status_code_difference=sd,
            response_length_difference_ratio=round(lr,4),
            elapsed_time_difference_ratio=round(er,4),
            body_fingerprint_difference=bd,
            sql_error_pattern=sql_error_count>0,
            repeatable=repeat,
            successful_requests=len(ok),
            total_requests=len(results)
        )

        if not ok:
            v,reason="execution_failed","모든 SQLI 요청 실패"
        elif all_sql_errors:
            # 모든 true/false 요청이 동일한 500 SQL 오류라면 boolean 비교 증거가 아니다.
            # 다만 입력이 SQL 오류를 일으킨다는 error-based 신호는 존재한다.
            if repeat and boolean_difference:
                v,reason="inconclusive","모든 페이로드가 SQL 오류를 발생시켜 boolean 판정 불가; error-based SQLI 신호는 관찰됨"
            else:
                v,reason="inconclusive","true/false 모두 동일한 SQL 오류 응답; boolean SQLI 증거로 사용할 수 없음"
        elif repeat and boolean_difference:
            v,reason="supporting","2개 true/2개 false 그룹에서 정규화된 반복 가능 boolean/behavior 차이 확인"
        elif repeat:
            v,reason="contradicting","정규화 후 true/false 그룹이 반복적으로 동일한 동작"
        else:
            v,reason="inconclusive","개별 payload 반복성 또는 역할 그룹 일관성이 부족함"

        return self._record(c,"boolean_response_comparison",results,obs,v,reason)

    def _xss(self,c,results):
        ok=[r for r in results if r.execution_error is None]
        markers=[r for r in ok if r.payload_role=="reflection_marker"]; controls=[r for r in ok if r.payload_role=="control"]
        contexts=sorted({x for r in markers for x in r.reflection_contexts}); dangerous=sorted({x for r in markers for x in r.dangerous_contexts})
        repeat=all(self._stable([r for r in markers if r.payload_id==pid]) for pid in {r.payload_id for r in markers}) and self._stable(controls)
        sd,lr,er,bd=self._compare(controls,markers)
        obs=VerificationObservations(status_code_difference=sd,response_length_difference_ratio=round(lr,4),
            elapsed_time_difference_ratio=round(er,4),body_fingerprint_difference=bd,sql_error_pattern=False,
            reflected=any(r.reflected for r in markers),escaped_reflection=any(r.escaped_reflection for r in markers),
            reflection_contexts=contexts,dangerous_contexts=dangerous,repeatable=repeat,
            successful_requests=len(ok),total_requests=len(results))
        if not ok: v,reason="execution_failed","모든 XSS 요청 실패"
        elif dangerous and repeat: v,reason="supporting","위험 문맥 반복 반사: "+", ".join(dangerous)
        elif obs.escaped_reflection and repeat: v,reason="contradicting","마커가 HTML 이스케이프됨"
        elif obs.reflected: v,reason="inconclusive","원문 반사는 있으나 위험 문맥/반복성 부족"
        else: v,reason="contradicting","반사 마커 미검출"
        return self._record(c,"dangerous_context_check",results,obs,v,reason)

    def _bac(self,c,results):
        ok=[r for r in results if r.execution_error is None]; resources={r.value:r for r in c.resources}
        mismatches=[]; role_bypass=False; resource_bypass=False
        for r in ok:
            if r.expected_access=="deny" and r.access_granted:
                d=resources.get(r.payload)
                if d and d.required_role and r.auth_role!=d.required_role:
                    role_bypass=True; mismatches.append(f"role={r.auth_role} accessed {r.payload}, required={d.required_role}")
                if d and d.owner_principal_id and r.principal_id!=d.owner_principal_id:
                    resource_bypass=True; mismatches.append(f"principal={r.principal_id} accessed owner={d.owner_principal_id} resource={r.payload}")
        groups=defaultdict(list)
        for r in ok: groups[(r.payload_id,r.auth_context_id)].append(r)
        repeat=bool(groups) and all(self._stable(v) for v in groups.values())
        controls=[r for r in ok if r.payload_role=="authorization_control"]; variants=[r for r in ok if r.payload_role=="authorization_variant"]
        sd,lr,er,bd=self._compare(controls,variants)
        obs=VerificationObservations(status_code_difference=sd,response_length_difference_ratio=round(lr,4),
            elapsed_time_difference_ratio=round(er,4),body_fingerprint_difference=bd,sql_error_pattern=False,
            role_bypass_detected=role_bypass,resource_bypass_detected=resource_bypass,
            authorization_mismatches=sorted(set(mismatches)),repeatable=repeat,
            successful_requests=len(ok),total_requests=len(results))
        if not ok: v,reason="execution_failed","모든 BAC 요청 실패"
        elif (role_bypass or resource_bypass) and repeat: v,reason="supporting","예상 deny 역할/리소스 조합에서 반복 접근 허용"
        elif repeat and not mismatches: v,reason="contradicting","역할/리소스 정책과 응답 일치"
        else: v,reason="inconclusive","권한 불일치 반복성 또는 판정 정보 부족"
        return self._record(c,"role_resource_comparison",results,obs,v,reason)

    async def verify(self,candidate,validation):
        typ={VulnerabilityType.SQLI:"boolean_response_comparison",VulnerabilityType.XSS:"dangerous_context_check",VulnerabilityType.BAC:"role_resource_comparison"}[candidate.vulnerability_type]
        if not validation.executable:
            return self._record(candidate,typ,[],empty_obs(),"execution_failed","Validator executable=false")
        results=await self._execute(candidate,validation)
        if candidate.vulnerability_type==VulnerabilityType.SQLI: return self._sqli(candidate,results)
        if candidate.vulnerability_type==VulnerabilityType.XSS: return self._xss(candidate,results)
        return self._bac(candidate,results)
