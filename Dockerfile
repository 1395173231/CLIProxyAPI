FROM golang:1.25-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
  -ldflags="-s -w -X 'main.Version=${VERSION}' -X 'main.Commit=${COMMIT}' -X 'main.BuildDate=${BUILD_DATE}'" \
  -o /out/CLIProxyAPI ./cmd/server/

FROM alpine:3.22.0

RUN apk add --no-cache tzdata ca-certificates

# 数据目录（会被 volume/文件挂载）
RUN mkdir -p /CLIProxyAPI/pgstore

# 二进制放到“不会被 /CLIProxyAPI 挂载遮住”的路径
COPY --from=builder /out/CLIProxyAPI /usr/local/bin/CLIProxyAPI
RUN chmod +x /usr/local/bin/CLIProxyAPI

COPY config.example.yaml /CLIProxyAPI/config.example.yaml

ENV TZ=Asia/Shanghai
RUN cp /usr/share/zoneinfo/${TZ} /etc/localtime && echo "${TZ}" > /etc/timezone

EXPOSE 8317

# 仍然可以把工作目录设为 /CLIProxyAPI（如果程序依赖相对路径）
WORKDIR /CLIProxyAPI

CMD ["/usr/local/bin/CLIProxyAPI"]
