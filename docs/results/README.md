# VulnSpider 결과 팩

보고서·시연에 싣는 모든 수치의 **단일 출처**. 아래 실행을 한 번에 캡처한다.

| 항목 | 값 |
| --- | --- |
| 생성 시각 | 2026-08-30 11:19 UTC |
| VulnSpider 버전 | 0.1.0 |
| git 커밋 | 7423867 |
| Python | 3.12.6 |
| 검증 모델 | 있음 (data/corpus/verification-model.json) |
| 랜덤 예측기 | per-input-point, safe-weight 4, 시드 0, 1000 trials |

각 시나리오 폴더에는 `dashboard.html`, `verification-detail.html`, `evaluation.json`, `evaluation-table.{md,html}`(3-arm 비교), `evaluation-inputs.{md,html}`(입력점별 취약 유형), `command.txt`, `run.log`가 들어 있다.

> 참고: DemoShop에서는 검증 전 랭킹이 이미 최적(MAP@K=1.0)이라 `VulnSpider (full pipeline)`과 `without focused verification`의 랭킹 지표가 **동일**하다 — 재정렬할 여지가 없기 때문이다. Focused verification의 기여는 랭킹 재정렬이 아니라 각 후보의 **confidence 값**(대시보드·`verification-detail.html`)과 prior가 오정렬하는 더 어려운 타깃(DVWA: 0.875→0.950)에서 드러난다.

## DemoShop — 공개 상점 (Static + Focused Verification)

- 대상: `http://127.0.0.1:8899/`
- 폴더: [`demoshop/`](demoshop/)
- 상태: **ok**

```bash
PYTHONPATH=src python -m vulnspider analyze --url http://127.0.0.1:8899/ --top-k 10 --max-pages 40 --max-requests 220 --output docs/results/demoshop/analysis.json --html-output docs/results/demoshop/dashboard.html --verify --verification-model data/corpus/verification-model.json --verify-output docs/results/demoshop/verification.json --verify-detail-output docs/results/demoshop/verification-detail.html --ground-truth data/demo/demoshop-ground-truth.json --application-id demoshop --eval-output docs/results/demoshop/evaluation.json --random-predictor --random-safe-weight 4
```

| Arm | P@1 | R@1 | MAP@1 | P@5 | R@5 | MAP@5 |
| --- | --- | --- | --- | --- | --- | --- |
| Random predictor | 0.160 | 0.005 | 0.160 | 0.160 | 0.025 | 0.087 |
| VulnSpider without focused verification | 1.000 | 0.031 | 1.000 | 1.000 | 0.156 | 1.000 |
| **VulnSpider (full pipeline)** | 1.000 | 0.031 | 1.000 | 1.000 | 0.156 | 1.000 |
| Random predictor (per-input-point type guess) | 0.161 | 0.005 | 0.161 | 0.161 | 0.025 | 0.087 |

## DemoShop — 인증 영역 BAC (`/portal/`, user 세션)

- 대상: `http://127.0.0.1:8899/portal/`
- 폴더: [`demoshop-bac/`](demoshop-bac/)
- 상태: **ok**

```bash
PYTHONPATH=src python -m vulnspider analyze --url http://127.0.0.1:8899/portal/ --access-control --cookie demoshop_session=<redacted> --top-k 10 --max-pages 20 --max-requests 100 --output docs/results/demoshop-bac/analysis.json --html-output docs/results/demoshop-bac/dashboard.html --verify --verification-model data/corpus/verification-model.json --verify-output docs/results/demoshop-bac/verification.json --verify-detail-output docs/results/demoshop-bac/verification-detail.html --ground-truth data/demo/demoshop-ground-truth.json --application-id demoshop --eval-output docs/results/demoshop-bac/evaluation.json --random-predictor --random-safe-weight 4
```

| Arm | P@1 | R@1 | MAP@1 | P@5 | R@5 | MAP@5 |
| --- | --- | --- | --- | --- | --- | --- |
| Random predictor | 0.222 | 0.111 | 0.222 | 0.222 | 0.556 | 0.291 |
| VulnSpider without focused verification | 1.000 | 0.500 | 1.000 | 0.400 | 1.000 | 1.000 |
| **VulnSpider (full pipeline)** | 1.000 | 0.500 | 1.000 | 0.400 | 1.000 | 1.000 |
| Random predictor (per-input-point type guess) | 0.239 | 0.120 | 0.239 | 0.224 | 0.561 | 0.301 |
