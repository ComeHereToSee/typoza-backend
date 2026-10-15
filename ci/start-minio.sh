#!/usr/bin/env bash
# 启动测试用 MinIO(S3 兼容对象存储),等待健康检查通过;失败时打印容器日志。
set -euo pipefail
docker run -d --name minio -p 9000:9000 \
  -e MINIO_ROOT_USER="${TYPOZA_TEST_S3_ACCESS_KEY:?}" \
  -e MINIO_ROOT_PASSWORD="${TYPOZA_TEST_S3_SECRET_KEY:?}" \
  minio/minio:latest server /data
for _ in $(seq 1 60); do
  if curl -sf http://localhost:9000/minio/health/live >/dev/null; then echo "minio ready"; exit 0; fi
  sleep 1
done
docker logs minio || true
echo "minio 60 秒内未就绪" >&2
exit 1
