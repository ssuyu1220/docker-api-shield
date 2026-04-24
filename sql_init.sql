CREATE TABLE IF NOT EXISTS security_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(50),
    req_path VARCHAR(50),
    ja3_fingerprint VARCHAR(32),
    ja4_fingerprint VARCHAR(64),
    decision BOOLEAN,
    deny_report JSONB,
    decoded_snippets JSONB,
    raw_data JSONB 
);

-- 建立一個索引，讓查詢比較快 (選做)
CREATE INDEX IF NOT EXISTS idx_timestamp ON security_logs(timestamp);