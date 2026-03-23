# Build Stage
FROM golang:1.21-alpine AS builder
WORKDIR /app

COPY main.go .

# 1. 這裡補一行 init，在容器裡自動產生 go.mod (騙過編譯器，解決報錯)
RUN go mod init crypto-service

RUN CGO_ENABLED=0 go build -o crypto-service main.go

# Final Stage
# 2. 這裡改用 alpine，因為 Trivy 需要 SSL 憑證下載 DB，用 scratch 會因為沒憑證而失敗
FROM alpine:latest

# 安裝憑證 (讓 Trivy 可以上網更新資料庫)
RUN apk --no-cache add ca-certificates

# 3. 把 Trivy 搬進來 (從 GHCR 搬，避開 DockerHub 限制)
COPY --from=ghcr.io/aquasecurity/trivy:latest /usr/local/bin/trivy /usr/local/bin/trivy

COPY --from=builder /app/crypto-service /crypto-service
EXPOSE 8082
ENTRYPOINT ["/crypto-service"]