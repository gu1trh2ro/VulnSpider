# Local model files

이 폴더는 로컬 파인튜닝 LLM payload proposer(`--verify-proposer llm`)가 사용하는
**대용량 바이너리**를 두는 곳입니다. 파일 자체는 git에 커밋되지 않습니다
(`.gitignore`에서 `*.gguf`, `*.whl` 제외).

## 여기에 저장할 파일

HuggingFace `lsk0228/vulnspider-3b_v3 또는 lsk0228/vulnspider-llama3.1-8b`(게이트 저장소, 로그인 필요)에서 받습니다:

| 파일 | 용도 |
|---|---|
| `vulnspider-3b_v3.gguf` | 파인튜닝 3b 모델 (llama.cpp GGUF) |
| `vulnspider-llama3.1-8b.gguf` | 파인튜닝 8b 모델 (llama.cpp GGUF) |
| `llama_cpp_python-0.3.34-py3-none-win_amd64.whl` | 프리빌트 실행 엔진 (Windows / Python 3) |

받는 URL:

- <https://huggingface.co/lsk0228/vulnspider-3b_v3/resolve/main/vulnspider-3b_v3.gguf>
- <https://huggingface.co/lsk0228/vulnspider-3b_v3/resolve/main/vulnspider-llama3.1-8b.gguf>
- <https://huggingface.co/lsk0228/vulnspider-3b_v3/resolve/main/llama_cpp_python-0.3.34-py3-none-win_amd64.whl>

## 저장 후 사용법

```powershell
# 1) 실행 엔진 설치 (프리빌트 wheel)
(README_DYNAMIC_TESTING.md를 참고)

# 2) 빠른 모델 sanity 체크 (네트워크 요청 없음)
$env:PYTHONPATH = "src"


# 3) 실전 end-to-end (loopback 데모 서버 대상)
python demo_target_server.py            # 별도 창: http://127.0.0.1:8899
python -m vulnspider.cli --url http://127.0.0.1:8899/ `
    --verify --verify-proposer llm `
    --llm-model .\models\vulnspider-3b_v3.gguf `
    --verify-output verify-llm.json
```

모델 경로는 `--llm-model`로 직접 주거나 `VULNSPIDER_LLM_MODEL` 환경변수로 지정할 수 있습니다.
LLM이 제안한 페이로드도 전송 전에 반드시 deterministic `PayloadValidator`를 통과합니다.
