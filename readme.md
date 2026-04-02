# 針對暴露 Docker API 之抗混淆與自動化防禦機制
## 部屬方法
### 1. 設定環境變數
在專案根目錄建立 `.env` 檔案，並設定資料庫使用者名稱跟密碼、Qroq API KEY：
```
POSTGRES_USER=your_database_user_name
POSTGRES_PASSWORD=your_database_user_password
GROQ_API_KEY=your_groq_api_key
```
### 2. 設定 NAT
此服務預設部屬於兩個 port，分別是

* 8443 port：有開啟 TLS
* 8080 port：無開啟 TLS

因此需將欲受保護的系統設定為會經過其中一個

### 3. 使用 Docker 部屬與啟動服務
執行以下指令編譯並啟動所有服務
```
sudo docker compose up -d --build
```
