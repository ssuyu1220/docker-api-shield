import psycopg2
import aisuite as ai
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import json

app = Flask(__name__)
CORS(app)
api_key = os.environ.get("GROQ_API_KEY")
if not api_key:
    raise ValueError("找不到 GROQ_API_KEY，請確認環境變數設定！")
provider = "groq"
model = "llama-3.3-70b-versatile"

def reply(log_id):
    client = ai.Client()
    system="""
# Role
你是一位資深的雲端安全分析師 (Cloud Security Analyst) 與威脅獵捕專家 (Threat Hunter)，專精於容器安全 (Docker/K8s)、Linux 鑑識與網路攻防分析。

# Task
你的任務是分析使用者提供的安全性日誌 (Security Logs)。你需要：
1. **行為解碼**：自動識別並解碼 Base64、Hex 或其他混淆指令。
2. **風險評估**：根據攻擊路徑（如 MITRE ATT&CK 框架）判斷攻擊階段。
3. **逃逸偵測**：特別留意 Host Root 綁定、權限提升或敏感目錄掛載。
4. **威脅通報**：總結攻擊者的意圖，並提供具體的補救與防禦建議。

# Analysis Guidelines
- **關鍵行為分析**：解釋為什麼某些行為是危險的（例如：為什麼掛載 /:/hostroot 是嚴重的）。
- **通訊追蹤**：分析指令中的 IP、域名或 .onion 網址的用途。
- **簡潔明瞭**：使用結構化的格式進行回報，區分「威脅等級」、「攻擊意圖」與「具體指令分析」。

# Response Format
請統一使用以下格式回報：
- **【威脅等級】**：(低/中/高/緊急)
- **【攻擊意圖總結】**：一句話說明發生了什麼。
- **【詳細行為分解】**：針對指令中的關鍵步驟進行解釋。
- **【防禦建議】**：針對此漏洞該如何修補。
"""
    prompt=prompt_generator(log_id)
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt}
    ]


    response = client.chat.completions.create(model=f"{provider}:{model}", messages=messages)
    #print(prompt)
    #print(response.choices[0].message.content)
    return response.choices[0].message.content


 
def prompt_generator(log_id):
    try:
        conn = psycopg2.connect(
        host="postgres",
        database="crypto_db",
        user=os.environ.get("POSTGRES_USER", "root"),
        password=os.environ.get("POSTGRES_PASSWORD"),
        )
        cur = conn.cursor()
        
        # 排除 ID，取出所有關鍵安全欄位
        query = """
            SELECT timestamp, source_ip, ja3_fingerprint, ja4_fingerprint, 
                   decision, deny_report, decoded_snippets, raw_data 
            FROM security_logs 
            WHERE id = %s;
        """
        cur.execute(query, (log_id,))
        rows = cur.fetchall()

        formatted_output = []

        for row in rows:
            ts, ip, ja3, ja4, decision, deny, snippets, raw = row
            
            # 格式化為 AI 友善的文字塊
            log_entry = f"""
### 🚨 安全事件報告 [{ts}]
- **來源 IP**: {ip}
- **TLS 指紋**: 
  - JA3: `{ja3}`
  - JA4: `{ja4}`
- **防禦決策**: {"🟢 放行 (ALLOW)" if decision else "🔴 阻擋 (DENY)"}

#### 🛑 阻擋理由 (OPA Report):
{json.dumps(deny, indent=2, ensure_ascii=False)}

#### 🔍 惡意解碼片段 (Malicious Snippets):
{json.dumps(snippets, indent=2, ensure_ascii=False) if snippets else "無解碼片段"}

#### 📦 原始請求內容:
{json.dumps(raw, indent=2, ensure_ascii=False)}
---
"""
            formatted_output.append(log_entry)

        return "\n".join(formatted_output)

    except Exception as e:
        return f"讀取失敗: {e}"
    finally:
        if conn:
            conn.close()  

@app.route('/analyze/<int:log_id>', methods=['GET'])
def analyze_event(log_id):
    return jsonify({
        "analysis_report": reply(log_id),
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)