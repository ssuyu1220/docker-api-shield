# db_pass/app.py
from flask import Flask, request
import psycopg2
import json
import datetime

app = Flask(__name__)

# DB 連線設定
def get_db_connection():
    return psycopg2.connect(
        host="postgres",
        database="crypto_db",
        user="root",
        password="**ncu112502535postgredb**"
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
        response_code = data.get('response_code')
        deny_report_json = json.dumps(data.get('deny_report', []))
        raw_data_json = json.dumps(data.get('original_packet', {}))
        print(deny_report_json, flush=True)
        decision = True
        if str(response_code) == '403':
            decision = False

        with conn:
            with conn.cursor() as cur:

                insert_sql = """
                    INSERT INTO security_logs 
                    (timestamp, source_ip, ja3_fingerprint, decision, deny_report, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                
                cur.execute(insert_sql, (
                    timestamp, 
                    client_ip,
                    ja3_fingerprint, 
                    decision, 
                    deny_report_json,
                    raw_data_json
                ))

        return "Saved", 200

    except Exception as e:
        print(f"DB Error: {e}")
        return "Error", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)