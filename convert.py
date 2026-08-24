import json

def convert_crawl_to_registry(crawl_file_path, output_path):
    # 1. 크롤링 결과 파일 읽기
    with open(crawl_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 안전하게 데이터 구조 파악
    discovery = data.get("crawl", {}).get("discovery", {})
    input_points_raw = discovery.get("input_points", [])
    endpoints_raw = discovery.get("endpoints", [])
    contexts_map = discovery.get("input_point_request_contexts", [])
    templates_raw = discovery.get("request_templates", [])

    # 템플릿 매핑 (ID -> 템플릿 데이터)
    templates_dict = {t["id"]: t for t in templates_raw}

    # Input Point ID -> 템플릿 정보 매핑 (메소드와 URL을 찾기 위해)
    ip_to_template = {}
    for ctx in contexts_map:
        ip_id = ctx.get("input_point_id")
        rt_id = ctx.get("request_template_id")
        if ip_id and rt_id and rt_id in templates_dict:
            ip_to_template[ip_id] = templates_dict[rt_id]

    registry = {
        "input_points": {},
        "endpoints": {}
    }

    # 2. Input Points 변환 (배열 -> 딕셔너리)
    for ip in input_points_raw:
        ip_id = ip["id"]
        template = ip_to_template.get(ip_id, {})

        registry["input_points"][ip_id] = {
            "method": template.get("method", "GET"),
            "url": template.get("url", ip.get("source_page")),
            "parameter_name": ip.get("name"),
            "parameter_location": ip.get("location", "").lower(),
            "parameter_occurrence": ip.get("occurrence_index") or 0,
            "original_value": ip.get("baseline_value"),
            "body": None
        }

    # 3. Endpoints 변환 (배열 -> 딕셔너리)
    for ep in endpoints_raw:
        ep_id = ep["id"]
        
        # 현재 환경에서는 스캐너가 토큰이나 세부 권한을 직접 보관하지 않으므로,
        # Mutation 검증기가 요구하는 기본 BAC(권한 통제) 테스트용 뼈대를 채워줌
        registry["endpoints"][ep_id] = {
            "method": ep.get("method", "GET"),
            "url": f"{ep.get('scheme', 'http')}://{ep.get('host', '')}{ep.get('path', '')}",
            "parameter_name": None,
            "parameter_location": "query",
            "parameter_occurrence": 0,
            "original_value": None,
            "body": None,
            "baseline_auth_context_id": "authenticated_user",
            "resources": [],
            "auth_contexts": [
                {"context_id": "authenticated_user", "role": "user", "is_anonymous": False},
                {"context_id": "anonymous", "role": "anonymous", "is_anonymous": True},
                {"context_id": "admin", "role": "admin", "is_anonymous": False}
            ]
        }

    # 4. 결과물 저장
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(registry, f, indent=2)
    print(f"✅ 변환 완료! {output_path} 파일이 예쁘게 생성되었습니다.")

# 스크립트 실행 (파일명은 실제 환경에 맞게 수정)
if __name__ == "__main__":
    convert_crawl_to_registry("./examples/vulnspider-crawl.json", "./examples/context_registry.json")