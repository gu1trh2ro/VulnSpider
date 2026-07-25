# Gemini verifier v3

- Payload 후보 수: 정확히 3개 또는 4개
- Validator: URL/포트/경로, destructive pattern, 길이, method, count/role 검사
- SQLI: 2 true + 2 false boolean/behavior 비교
- XSS: HTML text/attribute/URL/JavaScript/CSS/comment 위험 문맥 분석
- BAC: auth_contexts와 resources를 이용한 role/resource 비교

verifier 루트에서 실행:

```powershell
$env:PYTHONPATH="$PWD\src"
```1, 2, 3을 하나씩 실행하면 됩니다.```
1. python -m payload_verifier.cli examples\candidate_sqli.json --out output\sqli
2. python -m payload_verifier.cli examples\candidate_xss.json --out output\xss
3. python -m payload_verifier.cli examples\candidate_bac.json --out output\bac
```

기존 127.0.0.1:8899 데모 서버를 사용할 수 있습니다.


## v3.1 SQLI 판정 보정

- 에러 페이지에 payload 문자열이 반사되어 raw body hash가 달라지는 오탐을 방지하기 위해
  `normalized_body_sha256`을 추가했습니다.
- 모든 true/false 요청이 동일한 500 SQL 오류를 반환하면 boolean SQLI로 `supporting` 처리하지 않고
  `inconclusive`로 처리하며, reason에 error-based 신호를 표시합니다.
- 각 payload 반복성뿐 아니라 true 그룹 내부와 false 그룹 내부의 정규화 응답 일관성도 검사합니다.
