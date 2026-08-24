import json

SYSTEM_PROMPT = """You are a defensive payload mutation component for an
authorized web security verification pipeline.

Generate only safe and non-destructive verification values.

Never generate payloads that:
- modify, delete, insert, or extract data
- use stacked SQL queries
- use UNION-based SQL extraction
- use time-delay SQL functions
- execute JavaScript
- access cookies, localStorage, or sessionStorage
- load external resources
- create destructive HTTP requests
- invent resource identifiers
- invent authorization contexts
- modify the target host
- modify the target path
- modify the HTTP method

The application code will insert your generated value into
the exact input position.

Return JSON only."""

dataset = []
idx = 0

# -------------------------------------------------------------
# 1. SQL Injection (Numeric, String, Math, Boolean) - 40개
# -------------------------------------------------------------
sqli_templates = [
    # (method, url, param, loc, orig, payloads)
    ("GET", "http://127.0.0.1/item?id={val}", "id", "query", "{val}", [
        ("true_condition", "{val} AND 1=1", "Integer true boolean logic", "Normal response matching baseline."),
        ("false_condition", "{val} AND 1=2", "Integer false boolean logic", "Empty response or error."),
        ("true_condition", "{val_plus}-1", "Arithmetic equivalent expression", "Normal response matching baseline."),
        ("false_condition", "{val}-1", "Arithmetic non-equivalent expression", "Response for different ID.")
    ]),
    ("POST", "http://127.0.0.1/search", "q", "form", "{val}", [
        ("true_condition", "{val}' AND '1'='1", "String literal true boolean logic", "Normal search results matching baseline."),
        ("false_condition", "{val}' AND '1'='2", "String literal false boolean logic", "Empty search results."),
        ("syntax_error", "{val}'\"", "Safe quote imbalance syntax probe", "Database error or 500 response.")
    ]),
    ("GET", "http://127.0.0.1/api/user?name={val}", "name", "query", "{val}", [
        ("true_condition", "{val}' OR ('a'='a')", "String boolean true condition", "Normal user match."),
        ("false_condition", "{val}' AND ('a'='b')", "String boolean false condition", "No user match / 404."),
        ("reflection_probe", "{val}*1", "Type coercion verification probe", "Valid or type-mismatch signal.")
    ]),
    ("POST", "http://127.0.0.1/login", "username", "form", "{val}", [
        ("true_condition", "{val}' OR (1=1)--", "Standard boolean true with comment terminator", "Authentication bypass indicator."),
        ("false_condition", "{val}' AND (1=2)--", "Standard boolean false with comment terminator", "Invalid login error."),
        ("syntax_error", "{val}'", "Single quote syntax break", "Uncaught SQL syntax error.")
    ])
]

sample_values = [
    ("10", "11"), ("42", "43"), ("999", "1000"), ("7", "8"), ("105", "106"),
    ("admin", "admin"), ("test_user", "test_user"), ("guest", "guest"), ("item_alpha", "item_alpha"), ("report_2026", "report_2026")
]

for val, val_plus in sample_values:
    for method, url_t, param, loc, orig_t, pl_list in sqli_templates:
        if idx >= 40: break
        orig = orig_t.format(val=val)
        url = url_t.format(val=val)
        
        payloads_out = []
        for kind, v_t, rat, exp in pl_list:
            pval = v_t.format(val=val, val_plus=val_plus)
            payloads_out.append({
                "kind": kind,
                "value": pval,
                "auth_context_id": None,
                "rationale": rat,
                "expected_signal": exp
            })
            
        candidate = {
            "candidate_id": f"cand_gen_{idx}",
            "vulnerability_type": "SQLI",
            "metadata": {},
            "request_context": {
                "method": method,
                "url": url,
                "parameter_name": param,
                "parameter_location": loc,
                "original_value": orig
            },
            "access_context": None
        }
        
        entry = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Generate safe verification values for the following candidate.\n\nCandidate:\n{json.dumps(candidate, indent=2)}\n\n(Assume Type-specific rules are applied here)"},
                {"role": "assistant", "content": json.dumps({"payloads": payloads_out, "warnings": []}, indent=2)}
            ]
        }
        dataset.append(entry)
        idx += 1

# -------------------------------------------------------------
# 2. Reflected XSS (Tag, Attribute, JS Context, Encoding) - 35개
# -------------------------------------------------------------
xss_templates = [
    ("GET", "http://127.0.0.1/search?keyword={val}", "keyword", "query", "{val}", [
        ("reflection_control", "xss_control_{val}", "Baseline text reflection check", "Reflected exactly in body."),
        ("reflection_marker", "\"><x-vulnspider test=\"{val}\"></x-vulnspider>", "Attribute breakout using inert custom element", "Reflected safely without entity encoding."),
        ("reflection_marker", "' onfocus='x-probe", "Attribute boundary test with inert event handler", "Reflected without single-quote escaping.")
    ]),
    ("POST", "http://127.0.0.1/profile/edit", "nickname", "form", "{val}", [
        ("reflection_control", "nick_{val}", "Alphanumeric baseline check", "Normal text reflection."),
        ("reflection_marker", "</title><x-probe label=\"{val}\">", "HTML title context breakout", "Reflected without tag stripping."),
        ("reflection_marker", "%3Cx-probe%3E{val}%3C%2Fx-probe%3E", "URL-encoded markup probe", "Decoded and reflected into HTML.")
    ]),
    ("GET", "http://127.0.0.1/api/jsonp?callback={val}", "callback", "query", "{val}", [
        ("reflection_control", "{val}_func", "JavaScript alphanumeric identifier", "Reflected as function name."),
        ("reflection_marker", "{val}';//", "JavaScript string literal breakout with line comment", "Reflected without quote escaping."),
        ("reflection_marker", "</script><x-probe>{val}</x-probe>", "Script tag breakout using closing tag", "Breaks out of script context.")
    ])
]

xss_samples = ["query", "hello", "user_tag", "banner", "footer_text", "category_filter", "preview_mode", "view_name", "temp_token", "default_val", "header_title", "custom_id"]

for sval in xss_samples:
    for method, url_t, param, loc, orig_t, pl_list in xss_templates:
        if idx >= 75: break
        orig = orig_t.format(val=sval)
        url = url_t.format(val=sval)
        
        payloads_out = []
        for kind, v_t, rat, exp in pl_list:
            pval = v_t.format(val=sval)
            payloads_out.append({
                "kind": kind,
                "value": pval,
                "auth_context_id": None,
                "rationale": rat,
                "expected_signal": exp
            })
            
        candidate = {
            "candidate_id": f"cand_gen_{idx}",
            "vulnerability_type": "REFLECTED_XSS",
            "metadata": {},
            "request_context": {
                "method": method,
                "url": url,
                "parameter_name": param,
                "parameter_location": loc,
                "original_value": orig
            },
            "access_context": None
        }
        
        entry = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Generate safe verification values for the following candidate.\n\nCandidate:\n{json.dumps(candidate, indent=2)}\n\n(Assume Type-specific rules are applied here)"},
                {"role": "assistant", "content": json.dumps({"payloads": payloads_out, "warnings": []}, indent=2)}
            ]
        }
        dataset.append(entry)
        idx += 1

# -------------------------------------------------------------
# 3. Broken Access Control (IDOR & Credential Strip) - 25개
# -------------------------------------------------------------
bac_samples = [("10", "11"), ("200", "201"), ("501", "502"), ("88", "89"), ("1000", "1001")]

for cur_id, target_id in bac_samples:
    # IDOR (Identifier Substitution)
    candidate_idor = {
        "candidate_id": f"cand_gen_{idx}",
        "vulnerability_type": "BROKEN_ACCESS_CONTROL",
        "metadata": {"check_kind": "IDENTIFIER_SUBSTITUTION"},
        "request_context": None,
        "access_context": {
            "method": "GET",
            "url": f"http://127.0.0.1/account?id={cur_id}",
            "parameter_name": "id",
            "parameter_location": "query",
            "original_value": cur_id,
            "baseline_auth_context_id": "user_a",
            "resources": [{"value": cur_id}, {"value": target_id}],
            "auth_contexts": [
                {"context_id": "user_a"},
                {"context_id": "user_b"},
                {"context_id": "admin"},
                {"context_id": "anonymous", "is_anonymous": True}
            ]
        }
    }
    payloads_idor = [
        {"kind": "authorization_control", "value": cur_id, "auth_context_id": "user_a", "rationale": "Baseline access verification", "expected_signal": "200 OK"},
        {"kind": "authorization_variant", "value": target_id, "auth_context_id": "user_a", "rationale": "Horizontal cross-resource access attempt", "expected_signal": "403 Forbidden"},
        {"kind": "authorization_variant", "value": cur_id, "auth_context_id": "user_b", "rationale": "Horizontal cross-user access attempt", "expected_signal": "403 Forbidden"},
        {"kind": "authorization_variant", "value": target_id, "auth_context_id": "admin", "rationale": "Vertical administrative access", "expected_signal": "200 OK"}
    ]
    dataset.append({
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Generate safe verification values for the following candidate.\n\nCandidate:\n{json.dumps(candidate_idor, indent=2)}\n\n(Assume Type-specific rules are applied here)"},
            {"role": "assistant", "content": json.dumps({"payloads": payloads_idor, "warnings": []}, indent=2)}
        ]
    })
    idx += 1
    
    # Credential Strip (Unauthenticated Access)
    candidate_strip = {
        "candidate_id": f"cand_gen_{idx}",
        "vulnerability_type": "BROKEN_ACCESS_CONTROL",
        "metadata": {"check_kind": "CREDENTIAL_STRIP"},
        "request_context": None,
        "access_context": {
            "method": "GET",
            "url": f"http://127.0.0.1/admin/dashboard?id={cur_id}",
            "parameter_name": "id",
            "parameter_location": "query",
            "original_value": cur_id,
            "baseline_auth_context_id": "admin",
            "resources": [{"value": cur_id}],
            "auth_contexts": [
                {"context_id": "admin"},
                {"context_id": "anonymous", "is_anonymous": True}
            ]
        }
    }
    payloads_strip = [
        {"kind": "authorization_control", "value": cur_id, "auth_context_id": "admin", "rationale": "Baseline authenticated administrator access", "expected_signal": "200 OK"},
        {"kind": "authorization_variant", "value": cur_id, "auth_context_id": None, "rationale": "Unauthenticated access attempt (session/token stripped)", "expected_signal": "401 Unauthorized"}
    ]
    dataset.append({
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Generate safe verification values for the following candidate.\n\nCandidate:\n{json.dumps(candidate_strip, indent=2)}\n\n(Assume Type-specific rules are applied here)"},
            {"role": "assistant", "content": json.dumps({"payloads": payloads_strip, "warnings": []}, indent=2)}
        ]
    })
    idx += 1

# 100개 맞추기 (남은 부분 채우기)
while len(dataset) < 100:
    dataset.append(dataset[len(dataset) % 40])

# 파일 쓰기
with open("chatml_tuning_dataset_100.jsonl", "w", encoding="utf-8") as f:
    for entry in dataset[:100]:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

print(f"✅ 총 {len(dataset[:100])}개의 고품질 파인튜닝 데이터셋이 'chatml_tuning_dataset_100.jsonl' 파일로 저장되었습니다!")