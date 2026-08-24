import sys
from bs4 import BeautifulSoup

def extract_to_markdown(html_file_path):
    try:
        with open(html_file_path, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
    except FileNotFoundError:
        print(f"Error: {html_file_path} 파일을 찾을 수 없습니다.")
        return

    articles = soup.find_all('article', class_='finding')
    
    if not articles:
        print("취약점 후보를 찾을 수 없습니다.")
        return

    print("| 순위 / 유형 | 원본 요청 (엔드포인트 및 파라미터) | 변형 요청 (주입값 및 변경점) | 신뢰도 (검증 전 → 최종) | 순위 근거 (주요 Feature 기여도) |")
    print("| :--- | :--- | :--- | :--- | :--- |")

    for art in articles:
        # 1. 순위 및 유형 (<br> 대신 공백 사용)
        rank = art.find(class_='rank').get_text(strip=True) if art.find(class_='rank') else ""
        vtype = art.find(class_='vtype').get_text(strip=True) if art.find(class_='vtype') else ""
        rank_type_md = f"**{rank}** {vtype}"

        # 2. 원본 요청 (<br> 대신 공백 사용)
        ep_div = art.find(class_='ep')
        ep_md = ""
        if ep_div:
            ep_text = ep_div.get_text(separator="|", strip=True)
            parts = ep_text.split('|—|')
            if len(parts) == 2:
                ep_md = f"`{parts[0].strip()}` `{parts[1].strip()}`"
            else:
                ep_md = f"`{ep_text.replace('|', ' ')}`"

        # 3. 신뢰도
        pcaption = art.find(class_='pcaption')
        conf_md = pcaption.get_text(strip=True).split('·')[-1].strip() if pcaption else ""
        if "검증 후 최종 신뢰도" in pcaption.get_text():
            prio = art.find(class_='prio').get_text(strip=True)
            conf_md = f"{conf_md.replace('검증 전 ', '')} → {prio}"

        # 4. 순위 근거 (<br> 대신 쉼표와 공백 사용)
        rationale_md = ""
        lab_divs = art.find_all(class_='lab')
        for lab in lab_divs:
            if "순위 근거" in lab.get_text():
                why_div = lab.find_parent(class_='why')
                rows = why_div.find_all(class_='bar-row')
                features = []
                for row in rows:
                    label = row.find(class_='bar-label').get_text(strip=True)
                    val = row.find(class_='bar-value').get_text(strip=True)
                    features.append(f"`{label}` ({val})")
                rationale_md = ", ".join(features)
                break

        # 5. 변형 요청 정보 (<br> 대신 공백 사용)
        probe_md = ""
        rec_table = art.find('table', class_='rec')
        if rec_table:
            tds = rec_table.find_all('td', class_='pl')
            if len(tds) >= 2:
                probe_text = tds[1].get_text(strip=True)
                if "주입값:" in probe_text:
                    injected = probe_text.split("주입값:")[-1].strip()
                    probe_md = f"`{injected}` (주입 및 변경)"
                else:
                    probe_md = "(내용 참조)"

        print(f"| {rank_type_md} | {ep_md} | {probe_md} | {conf_md} | {rationale_md} |")

if __name__ == "__main__":
    extract_to_markdown('dashboard.html')