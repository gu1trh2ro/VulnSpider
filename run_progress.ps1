param (
    [Parameter(Mandatory=$true)]
    [string]$TargetUrl
)

$StartTime = Get-Date

$env:PYTHONPATH = "src"
cls

python -m vulnspider analyze --url $TargetUrl --top-k 8 --access-control `
    --verify --verify-proposer llm --llm-model models\vulnspider-llama3.1-8b.gguf `
    --output analysis.json --html-output dashboard.html --verify-output verify.json --open

python tools\verification_detail_report.py `
    --verify verify.json `
    --crawl vulnspider-crawl.json `
    --out verification-detail.html

$EndTime = Get-Date
$ElapsedTime = $EndTime - $StartTime

Write-Host "total time: $($ElapsedTime.Hours)h $($ElapsedTime.Minutes)m $($ElapsedTime.Seconds)s" -ForegroundColor Yellow