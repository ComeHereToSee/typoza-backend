# syntax=docker/dockerfile:1
# 多阶段构建:静态链接的二进制 + distroless nonroot 运行镜像(无 shell、无包管理器)。
# 在仓库根目录构建:docker build -f deploy/Dockerfile -t typoza-server .

FROM golang:1.26-bookworm AS build
WORKDIR /src
# 先只拷依赖清单,依赖层可缓存;sdk 是本地 replace 的子模块,go.mod 必须一并拷入。
COPY go.mod go.sum ./
COPY sdk/go.mod sdk/
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/typoza-server ./cmd/typoza-server \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/typoza-server /typoza-server
# 本地磁盘驱动(TYPOZA_BLOB_DRIVER=fs)的默认挂载点,属主为 nonroot(65532)。
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/typoza-server"]
