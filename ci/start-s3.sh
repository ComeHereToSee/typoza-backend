#!/usr/bin/env bash
# 启动测试用 S3 兼容对象存储。MinIO 官方镜像已从 Docker Hub 下架,改用 RustFS(兼容 MinIO / S3 接口),
# 使用其默认账号 rustfsadmin / rustfsadmin。等待端口可用;失败时打印容器日志。
set -euo pipefail
docker run -d --name s3 -p 9000:9000 rustfs/rustfs:latest
for _ in $(seq 1 90); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:9000/ || true)
  if [ "$code" != "000" ]; then echo "s3 ready (HTTP $code)"; exit 0; fi
  sleep 1
done
docker logs s3 || true
echo "S3 服务 90 秒内未就绪" >&2
exit 1
