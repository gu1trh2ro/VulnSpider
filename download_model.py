from huggingface_hub import hf_hub_download
import os

os.system("cls")

"""
hf_hub_download(
    repo_id="lsk0228/vulnspider-3b_v3",
    filename="llama_cpp_python-0.3.34-py3-none-win_amd64.whl",
    token="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", # 이 부분에 토큰을 입력합니다
    local_dir="." # 절대 경로 입력
)
"""
"""
hf_hub_download(
    repo_id="lsk0228/vulnspider-3b_v3",
    filename="vulnspider-3b_v3.gguf",
    token="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", # 이 부분에 토큰을 입력합니다
    local_dir="." # 절대 경로 입력
)
"""
hf_hub_download(
    repo_id="lsk0228/vulnspider-3b_v3",
    filename="vulnspider-llama3.1-8b.gguf",
    token="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", # 이 부분에 토큰을 입력합니다
    local_dir="." # 절대 경로 입력
)