# Payload Verifier Mutation

Gemini API를 이용해 상위 취약점 후보에 맞는
심층 검증용 페이로드 후보를 생성하는 모듈입니다.

이 프로젝트는 Mutation 단계까지만 수행합니다.

수행 범위:

1. result.json 읽기
2. 상위 후보 선택
3. context_registry.json과 요청 문맥 결합
4. Gemini API로 안전한 검증값 생성
5. 실제 파라미터 위치에 값 삽입
6. baseline_request 생성
7. mutated_request 생성
8. mutation_result.json 저장

실제 HTTP 요청은 전송하지 않습니다.

다음 단계:

- Payload Validator
- Focused Verification

## finetuned model, llama_cpp_python download link
https://huggingface.co/lsk0228/vulnspider-3b_v3/resolve/main/vulnspider-3b_v3.gguf
https://huggingface.co/lsk0228/vulnspider-3b_v3/resolve/main/llama_cpp_python-0.3.34-py3-none-win_amd64.whl

## 설치

가상환경 없이 실행하려면:

```powershell
pip install -r requirements.txt
pip install .\llama_cpp_python-0.3.34-py3-none-win_amd64.whl
```

또는 editable install:

```powershell
pip install -e .
```

## 실행

방법 1:

```powershell
$env:PYTHONPATH="$PWD\src"
python -m payload_verifier.cli examples\result.json --context examples\context_registry.json --out output\mutation_result.json --top-k 4
python -m payload_verifier.validation_cli output\mutation_result.json --context examples\context_registry.json --out output\validation_result.json
python -m payload_verifier.run_focused_verification output\validation_result.json --out output\focused_verification_result.json
```

방법 2:

```powershell
.\run_pipeline.ps1
```

## 출력

```text
output/mutation_result.json
```

## 주의

승인된 테스트 대상에 대해서만 사용하세요.

Gemini에는 실제 Cookie, JWT, Authorization 값을 전달하지 않습니다.
인증정보 대신 auth_context_id만 사용합니다.
