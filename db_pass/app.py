# db_pass/app.py
from flask import Flask, request
import psycopg2
import os
import json
import datetime
import time
import threading

app = Flask(__name__)

# DB 連線設定
DB_USER = os.environ.get("POSTGRES_USER", "root")
DB_PASS = os.environ.get("POSTGRES_PASSWORD")

if not DB_PASS:
    raise ValueError("請確認 .env 檔案中已設定 POSTGRES_PASSWORD")

def get_db_connection():
    return psycopg2.connect(
        host="postgres",
        database="crypto_db",
        user=DB_USER,
        password=DB_PASS
    )

@app.route('/save-to-db', methods=['POST'])
def save_to_db():
    data = request.get_json()
    conn = None
    try:
        conn = get_db_connection()
        
        timestamp = datetime.datetime.now()
        client_ip = data.get('client_ip')
        ja3_fingerprint = data.get('ja3_fingerprint', 'unknown')
        ja4_fingerprint = data.get('ja4_fingerprint', 'unknown')
        print(ja4_fingerprint)
        response_code = data.get('response_code')
        deny_report_json = json.dumps(data.get('deny_report', []))
        print(deny_report_json, flush=True)
        decoded_snippets_json = json.dumps(data.get('decode_snippets', {}))
        raw_data_json = json.dumps(data.get('original_packet', {}))
        
        decision = True
        if str(response_code) == '403':
            decision = False

        with conn:
            with conn.cursor() as cur:

                insert_sql = """
                    INSERT INTO security_logs 
                    (timestamp, source_ip, ja3_fingerprint, ja4_fingerprint, decision, deny_report, decoded_snippets, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
                
                cur.execute(insert_sql, (
                    timestamp, 
                    client_ip,
                    ja3_fingerprint,
                    ja4_fingerprint,
                    decision, 
                    deny_report_json,
                    decoded_snippets_json,
                    raw_data_json
                ))

        return "Saved", 200

    except Exception as e:
        print(f"DB Error: {e}")
        return "Error", 500
    
def auto_cleanup_db():
    print("[DB-PASS] Start daily cleaning", flush=True)
    while True:
        # 每天執行一次 (86400秒)
        #time.sleep(86400) 
        time.sleep(10)
        conn = None
        try:
            conn = psycopg2.connect(
                host="postgres",
                database="crypto_db",
                user=DB_USER,
                password=DB_PASS,
            )
            cur = conn.cursor()
            
            # 刪除 7 天前的資料
            delete_query = "DELETE FROM security_logs WHERE timestamp < NOW() - INTERVAL '7 days';"
            cur.execute(delete_query)
            conn.commit()
            
            deleted_rows = cur.rowcount
            print(f"[DELETE] delete {deleted_rows} out of date records", flush=True)
            
            cur.close()
        except Exception as e:
            print(f"[ERROR] error: {e}", flush=True)
        finally:
            if conn:
                conn.close()
if __name__ == '__main__':
    threading.Thread(target=auto_cleanup_db, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)