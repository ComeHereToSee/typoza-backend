# typoza-backend

Typoza 的云端保存服务(Go)。只负责「保存」:账号、端到端加密存储、多设备增量同步、历史版本、回收站。
服务器只见密文:文件内容与文件名都在客户端加密。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/sync-protocol.md](docs/sync-protocol.md) | 同步协议与加密规范 v1(服务端与客户端的唯一契约) |
| [api/openapi.yaml](api/openapi.yaml) | OpenAPI 3.1 接口描述 |
| [docs/architecture.md](docs/architecture.md) | 架构、包职责、数据流、扩展点、已知边界 |
| [docs/deploy.md](docs/deploy.md) | 自托管部署、密钥生成、备份恢复、升级 |

## 目录

```
cmd/typoza-server     服务入口
internal/             app 装配、httpapi、service、store、auth、blob、notify、ratelimit、retention、migrate 等
migrations/           内嵌的数据库迁移 SQL
sdk/                  客户端同步引擎(独立 Go 模块)
e2e/                  端到端测试
deploy/               Dockerfile、docker-compose、Caddyfile、.env.example
api/                  OpenAPI
```

## 快速自托管

```bash
cd deploy && cp .env.example .env   # 按注释生成并填写密钥与域名
docker compose up -d --build
```

详见 [docs/deploy.md](docs/deploy.md)。

## 开发与测试

构建与测试全部在 GitHub Actions 上完成;每个 job 的日志推送到 `ci/<job>` 分支。

- 单元测试不依赖外部服务。
- 集成测试在设置了 `TYPOZA_TEST_DATABASE_URL`(PostgreSQL 17)时运行,缺失则跳过;
  `TYPOZA_TEST_S3_ENDPOINT` / `TYPOZA_TEST_S3_ACCESS_KEY` / `TYPOZA_TEST_S3_SECRET_KEY` 齐全时用 MinIO,否则用本地磁盘。
  每个测试使用独立的随机 schema 与随机桶,可并行。
- 测试辅助:`internal/testutil.NewTestConfig(t testing.TB) config.Config`,配合
  `app.New(ctx, cfg, log)`、`(*App).Handler()`、`(*App).Close()` 即可在 httptest 中起一个完整实例。
