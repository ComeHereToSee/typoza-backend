# typoza-backend 自托管部署

> 适用:一台有公网 IP 的 Linux 服务器(2 核 2 GB 起),已装 Docker 与 Docker Compose v2,域名已解析到这台机器,80/443 端口对外开放。

## 1. 组成

`deploy/docker-compose.yml` 一次拉起四个容器:

| 服务 | 作用 | 数据卷 |
|---|---|---|
| `caddy` | 对外 80/443,自动申请与续期 HTTPS 证书,反代到 server | `caddydata`(证书)、`caddyconfig` |
| `server` | typoza-server(本仓库构建) | 无状态 |
| `postgres` | PostgreSQL 17,账号与同步元数据 | `pgdata` |
| `minio` | S3 兼容对象存储,块密文 | `miniodata` |

服务器只保存密文;即使数据卷整体泄露,没有用户主密码或恢复码也解不开文件内容。

## 2. 首次部署

```bash
git clone <本仓库> typoza-backend && cd typoza-backend/deploy
cp .env.example .env
```

生成密钥并填进 `.env`(每个值单独生成,不要复用):

```bash
openssl rand -hex 24      # POSTGRES_PASSWORD
openssl rand -hex 24      # MINIO_ROOT_PASSWORD
openssl rand -base64 32   # TYPOZA_JWT_PRIVATE_KEY
openssl rand -base64 32   # TYPOZA_DATA_KEY
openssl rand -base64 32   # TYPOZA_ENUM_SECRET
```

再填 `TYPOZA_DOMAIN`(如 `sync.example.com`)与 `ACME_EMAIL`。然后:

```bash
docker compose up -d --build
docker compose logs -f server      # 看到「开始监听」即启动完成
curl https://sync.example.com/healthz   # {"status":"ok"}
curl https://sync.example.com/readyz    # {"status":"ready"}
```

首次启动会自动建表(迁移)并在 MinIO 里创建 `typoza` 桶。

自用建议:在客户端注册完自己的账号后,把 `.env` 里的 `TYPOZA_REGISTRATION` 改成 `closed`,再 `docker compose up -d` 让它生效。

## 3. 密钥说明(务必离线备份 `.env`)

| 变量 | 丢失 / 泄露的后果 |
|---|---|
| `TYPOZA_JWT_PRIVATE_KEY` | 泄露可伪造访问令牌,立即更换;更换后所有设备需重新登录(刷新令牌仍有效,客户端会自动换新访问令牌) |
| `TYPOZA_DATA_KEY` | 丢失后已开启的二次验证无法校验,用户只能走恢复流程(会关闭二次验证);务必与数据库备份分开保管 |
| `TYPOZA_ENUM_SECRET` | 更换只会让未注册邮箱的假盐变化,不影响已注册账号 |
| `POSTGRES_PASSWORD` / `MINIO_ROOT_PASSWORD` | 容器内部使用;更换时需同时改容器内的账号口令 |

## 4. 全部环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `TYPOZA_LISTEN` | `:8080` | HTTP 监听地址 |
| `TYPOZA_METRICS_LISTEN` | 空 | 设置后 `/metrics` 只在该地址暴露;为空时挂在主端口 |
| `TYPOZA_DATABASE_URL` | 必填 | PostgreSQL 连接串 |
| `TYPOZA_BLOB_DRIVER` | `fs` | `s3` 或 `fs` |
| `TYPOZA_BLOB_FS_DIR` | fs 时必填 | 本地对象目录(镜像内默认可写目录为 `/data`) |
| `TYPOZA_S3_ENDPOINT` | s3 时必填 | `host:port`,不带协议 |
| `TYPOZA_S3_BUCKET` | s3 时必填 | 桶不存在会自动创建 |
| `TYPOZA_S3_ACCESS_KEY` / `TYPOZA_S3_SECRET_KEY` | s3 时必填 | |
| `TYPOZA_S3_REGION` | 空 | 为空时自动探测 |
| `TYPOZA_S3_USE_TLS` | `true` | 内网 MinIO 设 `false` |
| `TYPOZA_JWT_PRIVATE_KEY` | 必填 | Ed25519 32 字节种子,base64 |
| `TYPOZA_JWT_KEY_ID` | 公钥指纹 | JWT 头 `kid`;多实例自动一致 |
| `TYPOZA_DATA_KEY` | 必填 | 32 字节,base64 |
| `TYPOZA_ENUM_SECRET` | 必填 | 32 字节,base64 |
| `TYPOZA_REGISTRATION` | `open` | `open` / `closed` |
| `TYPOZA_QUOTA_BYTES` | 10737418240 | 新账号配额(字节) |
| `TYPOZA_TRUSTED_PROXIES` | 空 | 逗号分隔的 CIDR 或 IP;只信这些来源的 `X-Forwarded-For` |
| `TYPOZA_LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `TYPOZA_RATE_IP_PER_MINUTE` | 30 | 未认证接口每 IP;0 表示不限 |
| `TYPOZA_RATE_EMAIL_PER_MINUTE` | 10 | 登录、恢复每邮箱;二次验证每账号 |
| `TYPOZA_RATE_ACCOUNT_PER_MINUTE` | 1200 | 已认证接口每账号 |
| `TYPOZA_RETENTION_INTERVAL` | `1h` | 后台回收间隔;`0` 关闭 |
| `TYPOZA_RETENTION_VERSIONS` | 50 | 每文件保留的版本数 |
| `TYPOZA_RETENTION_VERSION_DAYS` | 90 | 历史版本保留天数(当前版本永远保留) |
| `TYPOZA_RETENTION_TRASH_DAYS` | 30 | 回收站保留天数 |
| `TYPOZA_RETENTION_CHUNK_GRACE` | `24h` | 无引用块的回收宽限期 |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | 空 | 设置后启用 OpenTelemetry 追踪(OTLP/HTTP) |

缺少必填项或格式错误时,服务启动即退出,并一次列出所有有问题的变量名(不回显值)。

## 5. 备份与恢复

需要一起备份的只有三样:**PostgreSQL**、**MinIO 数据**、**`.env`**。两份数据最好在同一时间点附近备份;先备数据库、后备对象存储更安全(对象只会多不会少,多出的会被块回收清理)。

```bash
cd deploy
# 数据库
docker compose exec -T postgres pg_dump -U typoza -Fc typoza > typoza-$(date +%F).dump
# 对象存储(停写或低峰期执行;也可用 mc mirror 推到异地)
docker run --rm -v deploy_miniodata:/data -v "$PWD":/backup busybox tar czf /backup/minio-$(date +%F).tgz -C /data .
```

> 卷名前缀是 compose 项目名(默认等于目录名 `deploy`),用 `docker volume ls` 确认。

恢复(在新机器上完成第 2 节、但先不要启动 server):

```bash
docker compose up -d postgres minio
docker compose exec -T postgres pg_restore -U typoza -d typoza --clean --if-exists < typoza-2026-10-16.dump
docker compose stop minio
docker run --rm -v deploy_miniodata:/data -v "$PWD":/backup busybox sh -c 'cd /data && tar xzf /backup/minio-2026-10-16.tgz'
docker compose up -d
```

`.env` 必须用原来那份(尤其 `TYPOZA_DATA_KEY` 与 `TYPOZA_JWT_PRIVATE_KEY`)。

## 6. 升级

```bash
cd typoza-backend && git pull
cd deploy && docker compose up -d --build server
```

- 数据库迁移在新版本启动时自动执行;多实例同时启动只有一个执行,其余等待。
- 迁移只追加、不回滚;升级前先按第 5 节做一次数据库备份。
- 停机时服务会处理完在途请求(最多 20 秒)再退出,WebSocket 连接以 1001 关闭,客户端会自动重连并补拉。

## 7. 水平扩容

server 无状态,可直接起多个副本(`docker compose up -d --scale server=3`,或在编排平台上部署多副本),Caddy 的 `reverse_proxy` 会负载均衡。注意:

- 所有副本必须使用同一份 `.env`(同一把 JWT 私钥与数据密钥)。
- 限流计数在各实例内存里,实际上限 = 单实例上限 × 副本数。
- 跨实例实时通知走 PostgreSQL LISTEN/NOTIFY,无需额外组件;后台回收任务用数据库锁保证同时只有一个副本在跑。

## 8. 不用 Docker 时

```bash
CGO_ENABLED=0 go build -trimpath -o typoza-server ./cmd/typoza-server
TYPOZA_DATABASE_URL=postgres://... TYPOZA_BLOB_DRIVER=fs TYPOZA_BLOB_FS_DIR=/var/lib/typoza \
TYPOZA_JWT_PRIVATE_KEY=... TYPOZA_DATA_KEY=... TYPOZA_ENUM_SECRET=... ./typoza-server
```

前面放任意支持 WebSocket 的 HTTPS 反向代理,并把代理地址写进 `TYPOZA_TRUSTED_PROXIES`。

## 9. 排查

- `docker compose logs server`:JSON 日志,每个请求带 `requestId`,与响应头 `X-Request-Id` 对应。
- `/readyz` 返回 503:看 server 日志里的「就绪检查失败」,通常是数据库或 MinIO 未就绪。
- 指标:`docker compose exec caddy wget -qO- http://server:9090/metrics`(指标端口不经 Caddy 对外)。
