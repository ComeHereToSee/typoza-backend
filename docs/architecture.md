# typoza-backend 架构说明

> 契约以 `docs/sync-protocol.md` 为准;接口清单见 `api/openapi.yaml`。本文讲服务端怎么实现、为什么这样实现、边界在哪。

## 1. 一句话

Go 模块化单体、无状态、可水平扩容:所有状态都在 PostgreSQL(元数据)与对象存储(块密文)里,同一份配置起任意多个实例,前面挂一个反向代理即可。服务器零知识,只见邮箱、密文、密文大小、时间戳与不透明 ID。

## 2. 包结构与职责

| 包 | 职责 |
|---|---|
| `cmd/typoza-server` | 入口:读配置、起 HTTP 服务(可选单独的指标端口)、收到 SIGTERM 后 20 秒优雅停机 |
| `internal/config` | 从环境变量组装配置;必填项缺失一次性全部报出;密钥不进日志 |
| `internal/app` | 装配:连库、跑迁移、开对象存储、启通知监听与后台回收、组装 HTTP 处理器;对外 `New / Handler / Close` |
| `internal/httpapi` | HTTP 边界:路由、中间件(请求 ID、访问日志与指标、panic 恢复、安全响应头、认证、限流、请求体上限)、输入校验、统一错误体 |
| `internal/service` | 业务层:注册登录、令牌轮换、恢复、改密、二次验证、设备、库、块、提交与变更;把仓储错误翻译成协议错误码 |
| `internal/store` | PostgreSQL 仓储(pgx/v5 + 连接池,手写参数化 SQL);需要原子性的操作在一个事务里完成 |
| `internal/auth` | 纯密码学:Argon2id 口令二次哈希、EdDSA JWT、刷新/恢复不透明令牌、TOTP(RFC 6238)、服务端数据加密(AES-256-GCM) |
| `internal/blob` | 对象存储接口与两个实现:S3 兼容(minio-go)、本地磁盘(os.Root 防穿越 + 临时文件 rename 原子写) |
| `internal/notify` | 进程内订阅中心 + PostgreSQL LISTEN/NOTIFY 跨实例广播 |
| `internal/ratelimit` | 内存令牌桶,按 IP / 邮箱 / 账号限流,空闲桶惰性清理 |
| `internal/retention` | 后台回收:裁剪历史版本、清空过期回收站、回收无引用块、清过期令牌 |
| `internal/migrate` + `migrations/` | 内嵌 SQL 的极简迁移器:版本表 + advisory lock |
| `internal/metrics` | Prometheus 指标(每个实例独立注册表) |
| `internal/apierr` | 协议错误码常量与错误类型 |
| `internal/ids` | UUID 生成与「规范小写」校验 |
| `internal/testutil` | 集成测试与 e2e 用的隔离配置(随机 schema、随机桶、随机密钥) |

依赖方向:`cmd → app → httpapi → service → store / auth / blob`,`store → notify`(提交时发通知),无环。

## 3. 请求链路

```
客户端 ─HTTPS─▶ Caddy ─HTTP─▶ observe(请求 ID / 客户端 IP / 安全头 / panic 恢复 / 访问日志 / 指标)
                                  └▶ ServeMux(Go 1.22 方法+路径路由)
                                        ├ limitIP ─▶ 未认证 handler(prelogin/register/login/refresh/recover)
                                        └ authed(JWT 校验 → 设备仍在登录 → 每账号限流)─▶ 已认证 handler
                                              handler:解码 + 边界校验 → service → store / blob → 编码
```

- 开启追踪时最外层再包一层 otelhttp。
- 认证中间件每个请求都查一次设备状态(同时最多每分钟刷新一次 `last_seen_at`),所以登出、吊销设备、改密、恢复之后,旧访问令牌立即失效,不必等 15 分钟过期。代价是每请求一次轻量查询。
- 客户端 IP:直连来源不在 `TYPOZA_TRUSTED_PROXIES` 内就直接用它;在的话从 `X-Forwarded-For` 右往左跳过受信代理,取第一个不受信地址。

## 4. 关键数据流

### 4.1 上传与提交

1. `chunks/check` 查缺失块 → 2. `PUT /v1/chunks/{id}` 上传缺失块 → 3. `commit`。

- **块上传**:先查记录(已存在直接 200,不重复计量)→ 预检配额 → 写对象(对象键 `chunks/<userId>/<chunkId>-<16 位随机十六进制>`)→ 事务里登记块并用条件更新累加用量(`used_bytes + size <= quota_bytes`,并发上传不会一起越过配额)。登记失败(超配额、被并发上传抢先)就删掉自己刚写的对象。
- **对象键带随机后缀的原因**:块回收与同一块的并发重传交错时,各自操作的是不同对象,不会出现一方删掉另一方刚写入对象的情况。
- **提交事务**:锁库行(`SELECT ... FOR UPDATE`)→ 比对 `baseVersion` 与 head(不符返回 409 并附 head)→ 对引用的块加共享锁并找出缺失块(缺失返回 400 `missing_chunks`)→ `UPDATE vaults SET seq = seq + 1 RETURNING seq` → 写 `files` 的 head 与 `file_versions` → `pg_notify`。
- 因为同一库的提交在库行锁下串行、且锁持有到提交为止,seq 的可见顺序与分配顺序一致,changes 不会「先读到大号、后出现小号」。

### 4.2 拉取

`GET changes?since=` 只查 `files.head_seq > since` 并连接 head 版本,所以每个文件只返回最新版本,按 seq 升序分页;`cursor` 是本页最后一条的 seq。

### 4.3 实时通知

提交事务里 `pg_notify('typoza_vault_changed', {userId, vaultId, seq})` → 每个实例一条专用连接 `LISTEN` → 进程内 Hub 按 userId 分发给该账号的 WebSocket 连接。通知只是提示,丢了不影响正确性(客户端收到后走 changes;断线重连先全量补拉)。订阅缓冲满时丢弃新通知是安全的:缓冲里已有待处理通知,客户端处理时拉到的 changes 必然覆盖被丢的那次提交。

### 4.4 令牌

- 访问令牌:EdDSA JWT,15 分钟;只接受 `alg=EdDSA` 且 `kid` 匹配,防算法混淆。
- 刷新令牌:`tzr_` + 32 随机字节,只存 SHA-256。每次刷新在事务里对旧令牌行加锁、标记已用、发新令牌(同一令牌链)。已用令牌再次出现 = 被盗用:吊销该设备全部令牌与设备本身并提交,再返回 `refresh_reuse`。
- 恢复令牌:`tzv_` + 32 随机字节,10 分钟、一次性;完成恢复时同账号其它未用恢复令牌一并作废。

### 4.5 二次验证

TOTP 密钥用 `TYPOZA_DATA_KEY` 做 AES-256-GCM 加密后入库,AAD 绑定账号 ID。校验允许 ±1 步,并要求步长严格大于 `totp_last_step`(原子条件更新),保证同一步长的验证码只能用一次。启用/关闭接口额外按每账号 10 次/分钟限流(已认证接口 1200 次/分钟的额度足以在数小时内暴力猜中 6 位码)。

### 4.6 后台回收

每实例按 `TYPOZA_RETENTION_INTERVAL`(默认 1 小时,启动 1 分钟后首轮)尝试 `pg_try_advisory_lock`,拿到锁的那个实例执行:

1. 裁剪历史版本:每文件保留最近 50 个且不早于 90 天,head 永远保留;
2. 永久删除进回收站满 30 天的文件;
3. 回收块:无引用且上传超过 24 小时。先 `FOR UPDATE SKIP LOCKED` 锁候选(正被提交共享锁定的块会被跳过),再用新快照二次确认无引用后删除记录、扣减用量,事务提交后再删对象(删对象失败只留孤儿对象,不会出现「记录在、对象没了」);
4. 删除过期的刷新与恢复令牌。

### 4.7 迁移

启动时用一条独立连接取 `pg_advisory_lock(hashtext(current_schema() || ':typoza-migrate'))`,按序号执行未执行的 `migrations/NNNN_*.sql`,每个文件一个事务。多实例同时启动时只有一个在迁移,其余等待。锁键带 schema 名,同库多 schema(并行测试)互不阻塞。

## 5. 数据库表(定稿)

| 表 | 说明 |
|---|---|
| `users` | 邮箱、KDF(jsonb)、authKey/恢复口令的 Argon2id 哈希与盐、两份包装后的 accountKey、TOTP 密文与状态、配额与用量 |
| `devices` | 设备;`revoked_at` 非空表示已登出或被吊销 |
| `refresh_tokens` | 刷新令牌摘要、令牌链 ID、到期/已用/吊销时间 |
| `recovery_tokens` | 恢复令牌摘要、到期/已用时间 |
| `vaults` | 库(客户端生成的 ID)、加密库名、库内 seq |
| `files` | 文件 head:当前版本号、当前 seq、是否删除、删除时间 |
| `file_versions` | 全部保留版本:加密清单、块 ID 列表(GIN 索引)、大小、提交设备 |
| `chunks` | 按账号隔离的块:大小、对象键、上传时间 |
| `audit_events` | 安全审计:注册、登录成功/失败、刷新令牌重放、改密、恢复、设备吊销、TOTP 变更 |
| `schema_migrations` | 已执行的迁移 |

外键全部 `ON DELETE CASCADE`:删账号级联删设备、令牌、库、文件、版本、块记录与审计事件;对象存储里的对象由业务层随后逐个删除。

## 6. 可观测性

- 日志:`log/slog` JSON 输出到 stdout;每个请求一条访问日志(请求 ID、方法、路径、路由模式、状态码、字节数、耗时、客户端 IP、账号 ID)。密钥、令牌、口令哈希、连接串不进日志。
- 指标:`/metrics`(Prometheus)。设置 `TYPOZA_METRICS_LISTEN` 时只在该地址暴露,主端口不暴露。主要指标:`typoza_http_requests_total`、`typoza_http_request_duration_seconds`、`typoza_ws_connections`、`typoza_rate_limited_total`、`typoza_retention_deleted_total`、`typoza_blob_delete_errors_total`、`typoza_notify_reconnects_total`,以及 Go 运行时与进程指标。
- 追踪:只在设置了 `OTEL_EXPORTER_OTLP_ENDPOINT`(或 `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`)时启用,OTLP/HTTP 导出,其余参数走 OpenTelemetry 标准环境变量。
- 探针:`/healthz`(进程存活)、`/readyz`(数据库与对象存储可用,失败细节只进日志)。

## 7. 扩展点

- **对象存储**:实现 `blob.Store`(Put/Get/Delete/Exists/Ping)即可接入新后端。
- **迁移**:在 `migrations/` 追加 `NNNN_说明.sql`,已发布的迁移文件不得修改。
- **限流与保留规则**:都可用环境变量调整(见 `docs/deploy.md`)。
- **限流跨实例共享**:目前是单实例内存计数;要跨实例共享时把 `ratelimit.Limiter` 换成基于 Redis 或 PostgreSQL 的实现,接口只有 `Allow(key)`。

## 8. 已知边界

- 限流按实例计数,多实例部署时实际上限 = 单实例上限 × 实例数(协议 §6 已文档化)。
- 历史版本裁剪每轮对 `file_versions` 全表开窗扫描,数据量很大时应改为按文件分批。
- 对象删除失败(块回收、删号)会留下孤儿对象,只记错误日志与 `typoza_blob_delete_errors_total`,目前没有自动补删任务。
- 通知监听连接断开到重连之间的提交不会推送;客户端靠重连后全量补拉兜底。
- 认证中间件每请求查一次设备表;单库 QPS 很高时可加短时缓存(会牺牲吊销的即时性)。
- 服务端不设 `ReadTimeout`/`WriteTimeout`(会误杀 WebSocket 与大块传输),慢速请求体攻击依赖请求体上限与前置反向代理。
- 永久删除的文件不会出现在 changes 里:离线很久、错过了墓碑又错过了永久删除的客户端,本地仍保留该文件;它若再提交,会得到 `version_conflict` 且 `head` 为 null,按新文件(baseVersion=0)重新提交即可。
