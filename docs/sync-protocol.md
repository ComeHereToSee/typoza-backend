# Typoza 同步协议与加密规范 v1

> 本文是 typoza-backend(服务端)与客户端同步引擎(`sdk/`,客户端仓库 vendored 一份)之间的**唯一契约**。
> 改动本文 = 改公共契约:两端同时改、同时测。字段名、HKDF info 串、AAD 串一个字符都不能差。

## 1. 设计目标与边界

- **零知识**:服务器只见账号邮箱、密文、密文大小、时间戳、不透明 ID。文件内容、文件名、目录结构都在客户端加密。
- **单人多设备**:没有协作、没有共享。冲突少见,但必须可检测、绝不静默覆盖。
- **离线优先**:客户端断网照常编辑;联网后增量同步。
- **可恢复**:忘记主密码时,用注册时生成的恢复码重置;两者都丢 = 云端数据不可解(本机文件不受影响)。
- **不在 v1**:密钥轮换(账户密钥泄露后整体重加密)、跨账号分享、网页端。

## 2. 密码学原语

| 用途 | 算法 | 参数 |
|---|---|---|
| 主密码派生 | Argon2id | 默认 内存 64 MiB(65536 KiB)、迭代 3、并行 4、输出 32 字节;盐 16 字节随机(注册时客户端生成) |
| 子密钥派生 | HKDF-SHA256(RFC 5869) | salt 为空,info 见下表,输出 32 字节 |
| 对称加密 | AES-256-GCM | nonce 12 字节随机,tag 16 字节 |
| 块 ID / 内容摘要 | HMAC-SHA256 | 输出转小写十六进制(64 字符) |
| 服务端口令哈希 | Argon2id | 内存 19 MiB、迭代 2、并行 1、输出 32 字节、每用户 16 字节随机盐 |
| 访问令牌签名 | Ed25519(JWT `alg=EdDSA`) | |

文本一律 UTF-8;主密码先做 Unicode NFC 规范化再进 Argon2id;邮箱一律 trim + 小写。
二进制放进 JSON 时用 **base64url 无填充**(RFC 4648 §5)。

### 2.1 密钥层级

```
主密码 ──Argon2id(salt, kdf 参数)──▶ masterKey(32B)
  masterKey ──HKDF "typoza/v1/auth"──▶ authKey      → 发给服务器(服务器再做一次 Argon2id 才入库)
  masterKey ──HKDF "typoza/v1/wrap"──▶ wrapKey      → 加密 accountKey,永不出本机

accountKey(32B 随机,注册时生成,全账号唯一数据主密钥)
  ──HKDF "typoza/v1/meta"────▶ metaKey     → 加密文件清单(manifest)与库名
  ──HKDF "typoza/v1/chunk"───▶ chunkKey    → 每块再派生:HKDF(chunkKey, info="typoza/v1/chunk/" + chunkId)
  ──HKDF "typoza/v1/chunk-id"▶ chunkIdKey  → HMAC 计算块 ID 与内容摘要

recoveryKey(32B 随机,注册时生成,只给用户看一次)
  ──HKDF "typoza/v1/recovery-wrap"─▶ recoveryWrapKey → 另包一份 accountKey
  ──HKDF "typoza/v1/recovery-auth"─▶ recoveryAuthKey → 发给服务器(服务器 Argon2id 后入库)
```

- 改主密码:只重新包装 accountKey(新 salt、新 authKey、新 encryptedAccountKey),数据不重加密。
- 恢复码显示格式:32 字节按 RFC 4648 Base32(大写字母表 `A-Z2-7`,无填充)得 52 字符,每 4 字符一组用 `-` 连接(13 组)。解析时忽略 `-`、空白,不区分大小写。

### 2.2 封装格式

**Seal(key, plaintext, aad)** → `0x01 ‖ nonce(12) ‖ ciphertext ‖ tag(16)`。首字节是格式版本号,当前只有 `0x01`;解析时遇到其它版本号必须报错,不得猜测。

| 对象 | 密钥 | 明文 | AAD(UTF-8 字节串) |
|---|---|---|---|
| encryptedAccountKey | wrapKey | accountKey | `typoza/v1/account-key` |
| recoveryEncryptedAccountKey | recoveryWrapKey | accountKey | `typoza/v1/account-key` |
| 库名 | metaKey | 库名 UTF-8 | `typoza/v1/vault-name\|` + vaultId |
| 文件清单 manifest | metaKey | 清单 JSON | `typoza/v1/manifest\|` + vaultId + `\|` + fileId + `\|` + 十进制 version |
| 数据块 | HKDF(chunkKey, `typoza/v1/chunk/` + chunkId) | `flags(1) ‖ payload` | `typoza/v1/chunk\|` + chunkId |

AAD 里的 `|` 是字面竖线字符;vaultId、fileId 是小写带连字符的 UUID 字符串。

### 2.3 数据块

- 文件明文按 **4 MiB(4194304 字节)** 定长切块,最后一块可以更短;空文件 0 块。
- `chunkId = hex(HMAC-SHA256(chunkIdKey, 原始块明文))`。同账号内相同块只存一份;HMAC 带密钥,服务器无法据此判断两个账号或已知文件的内容是否相同。
- `flags` 位 0 = payload 经 DEFLATE(RFC 1951,raw,无 zlib 头)压缩。客户端压缩后变小才置位,否则存原文。
- 下载后:解密 → 按 flags 解压 → 重算 HMAC,必须等于 chunkId,否则判定数据被篡改并报错(这一步同时防止服务器调换块)。
- 文件内容摘要 `contentHash = hex(HMAC-SHA256(chunkIdKey, "typoza/v1/file|" ‖ 全文件明文))`;组装完整文件后必须核对。

### 2.4 文件清单(manifest)明文

```json
{
  "path": "笔记/周报.md",
  "size": 1234,
  "mtime": "2026-10-16T01:02:03.123Z",
  "contentHash": "64 位小写十六进制",
  "chunks": ["chunkId", "..."],
  "deleted": false
}
```

- `path`:相对库根目录,`/` 分隔,NFC 规范化,不以 `/` 开头,不含 `.`、`..` 段。
- 删除墓碑:`deleted=true`,`chunks` 为空数组,`size=0`,`contentHash` 为空串,`path` 保留(回收站显示用)。
- 版本号:新文件 baseVersion=0 → version=1;每次提交 version = baseVersion + 1(服务器串行化同一文件的提交,冲突返回 409,所以客户端加密时就能确定 version)。

## 3. 传输与认证

- 只走 HTTPS(推荐 TLS 1.3);客户端仅对 `localhost` / `127.0.0.1` / `::1` 允许 http(开发自测)。
- 接口前缀 `/v1`,请求与响应体 `application/json; charset=utf-8`;数据块上传下载为 `application/octet-stream`。
- 认证头 `Authorization: Bearer <accessToken>`。
- 错误体统一:`{"error":{"code":"snake_case 错误码","message":"人读说明"}}`,另可带额外字段(见各接口)。

### 3.1 令牌

- **访问令牌**:JWT,头 `{"alg":"EdDSA","typ":"JWT","kid":"<密钥 ID>"}`,载荷 `iss="typoza"`、`aud="typoza-api"`、`sub=<userId>`、`did=<deviceId>`、`iat`、`exp`(15 分钟)。服务端只接受 `EdDSA`。
- **刷新令牌**:`tzr_` + base64url(32 随机字节)。服务器只存 SHA-256 摘要。有效期 30 天,每次刷新轮换(旧的标记已用,发新的);已用的旧令牌再次出现 = 被盗用,立即吊销该设备整条令牌链并返回 401 `refresh_reuse`。
- 客户端同一时刻只允许一个刷新请求在途(防止自身并发刷新触发误判)。

### 3.2 错误码

| HTTP | code | 含义 |
|---|---|---|
| 400 | `invalid_request` | 字段缺失或格式错 |
| 400 | `missing_chunks` | 提交引用了未上传的块;附 `"missing":["chunkId"]` |
| 401 | `unauthorized` | 未登录、令牌无效、账号或密码错误(不区分是哪项) |
| 401 | `token_expired` | 访问令牌过期,用刷新令牌换新 |
| 401 | `refresh_reuse` | 刷新令牌被重放,该设备已登出 |
| 401 | `totp_required` | 账号开启了二次验证,需带 `totpCode` 重试 |
| 401 | `totp_invalid` | 二次验证码错误 |
| 403 | `registration_closed` | 服务器关闭了注册 |
| 403 | `forbidden` | 无权访问该资源 |
| 404 | `not_found` | 资源不存在 |
| 409 | `email_taken` | 邮箱已注册 |
| 409 | `vault_exists` | 该库 ID 已存在 |
| 409 | `version_conflict` | baseVersion 不是当前版本;附 `"head":{版本对象}` |
| 409 | `not_deleted` | 永久删除只能作用于已在回收站的文件 |
| 413 | `payload_too_large` | 请求体超限 |
| 413 | `quota_exceeded` | 超出存储配额 |
| 429 | `rate_limited` | 请求过于频繁;带 `Retry-After` 头 |
| 500 | `internal` | 服务器内部错误(不回传细节,细节进服务端日志) |

## 4. 接口

### 4.1 账号

**POST /v1/auth/prelogin** `{"email"}` → `{"kdf":{"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4,"salt":"b64"}}`
未注册邮箱也返回 200:盐 = HMAC-SHA256(服务端枚举密钥, 规范化邮箱) 前 16 字节、参数为默认值,防止探测邮箱是否注册。

**POST /v1/auth/register**
```json
{
  "email": "a@b.c",
  "kdf": {"algorithm":"argon2id","memoryKiB":65536,"iterations":3,"parallelism":4,"salt":"b64"},
  "authKey": "b64(32B)",
  "encryptedAccountKey": "b64",
  "recoveryAuthKey": "b64(32B)",
  "recoveryEncryptedAccountKey": "b64",
  "device": {"name": "Z 的 MacBook Pro", "platform": "macos"}
}
```
→ 201 `会话对象`。KDF 参数下限:内存 ≥ 19456 KiB、迭代 ≥ 2、并行 1~16;低于下限返回 `invalid_request`。

**POST /v1/auth/login** `{"email","authKey","totpCode"?,"device":{"name","platform"},"deviceId"?}` → 200 `会话对象`。
带 `deviceId` 且属于该账号时复用设备记录(吊销其旧令牌链),否则新建设备。

会话对象:
```json
{
  "userId": "uuid", "deviceId": "uuid",
  "accessToken": "jwt", "accessTokenExpiresIn": 900,
  "refreshToken": "tzr_...",
  "encryptedAccountKey": "b64",
  "kdf": {...}
}
```

**POST /v1/auth/refresh** `{"refreshToken"}` → 200 `{"accessToken","accessTokenExpiresIn","refreshToken"}`。

**POST /v1/auth/logout**(需认证)→ 204,吊销当前设备令牌链。

**POST /v1/auth/recover/begin** `{"email","recoveryAuthKey"}` → 200 `{"recoveryEncryptedAccountKey","recoveryToken"}`(recoveryToken 10 分钟有效、一次性)。

**POST /v1/auth/recover/finish**
`{"recoveryToken","kdf","authKey","encryptedAccountKey","device":{...}}` → 200 `会话对象`。
效果:替换主密码相关字段、关闭二次验证、吊销所有设备令牌。恢复码本身不变。

**GET /v1/account** → `{"userId","email","totpEnabled","createdAt","usage":{"usedBytes","quotaBytes"}}`

**POST /v1/account/password** `{"authKey","newKdf","newAuthKey","newEncryptedAccountKey"}` → 204;吊销除当前设备外的所有设备令牌。

**DELETE /v1/account** `{"authKey"}` → 204;删除账号与全部数据(块、清单、设备)。

**POST /v1/account/totp/setup** → `{"secret":"Base32","otpauthUrl":"otpauth://totp/Typoza:<email>?secret=...&issuer=Typoza"}`(未启用前可重复调用,覆盖旧密钥)
**POST /v1/account/totp/enable** `{"code"}` → 204
**POST /v1/account/totp/disable** `{"code"}` → 204
TOTP:RFC 6238,SHA-1,6 位,30 秒步长,允许 ±1 步;同一步长的验证码只能用一次。

**GET /v1/devices** → `{"devices":[{"id","name","platform","createdAt","lastSeenAt","current":true}]}`
**DELETE /v1/devices/{deviceId}** → 204,吊销该设备令牌链。

### 4.2 库(vault)

一个「云同步文件夹」对应一个库。

**GET /v1/vaults** → `{"vaults":[{"id","encryptedName","seq","createdAt"}]}`
**POST /v1/vaults** `{"id":"客户端生成的 uuid","encryptedName":"b64"}` → 201 库对象(同 id 重复创建返回 409 `vault_exists`)
**DELETE /v1/vaults/{vaultId}** → 204,删除库及其全部清单(块由回收任务清理)

### 4.3 数据块

**POST /v1/chunks/check** `{"ids":["chunkId", ...]}`(≤ 1000 个)→ `{"missing":["chunkId"]}`
**PUT /v1/chunks/{chunkId}**,体为封装后的密文字节(≤ 4 MiB + 64 字节)→ 201(已存在返回 200,幂等)
**GET /v1/chunks/{chunkId}** → 200 密文字节
块按账号隔离:A 账号上传的块 B 账号不可见。chunkId 必须是 64 位小写十六进制。

### 4.4 文件提交与变更

**POST /v1/vaults/{vaultId}/files/{fileId}/commit**
```json
{"baseVersion": 2, "manifest": "b64", "chunks": ["chunkId"], "size": 1234, "deleted": false}
```
→ 200 `{"version":3,"seq":57}`
- `chunks` 与清单内的块列表一致(服务器看不到清单明文,靠它校验块是否齐全、做引用计数)。
- 冲突 → 409 `version_conflict`,附 `"head": 版本对象`。
- 块未上传 → 400 `missing_chunks`。

版本对象:`{"fileId","version","seq","manifest","deleted","size","deviceId","createdAt"}`

**GET /v1/vaults/{vaultId}/changes?since=<seq>&limit=<n>**(limit 默认 500,最大 1000)
→ `{"changes":[版本对象...],"cursor":<seq>,"hasMore":false}`
- 每个文件只返回**当前最新版本**(按其 seq 升序);cursor = 本页最后一条的 seq,无变化时等于 since。
- seq 按库单调递增,同一库的提交在事务内串行分配,保证不会出现「先读到大号、后提交小号」导致漏读。

**GET /v1/vaults/{vaultId}/files/{fileId}/versions** → `{"versions":[版本对象...]}`(新→旧)
恢复历史版本 = 客户端用旧清单内容以当前 head 为 baseVersion 重新提交(清单需用新 version 重新加密,AAD 变了)。

**GET /v1/vaults/{vaultId}/trash** → `{"files":[{"fileId","version","manifest","deletedAt"}]}`(墓碑清单,含原路径)
**DELETE /v1/vaults/{vaultId}/files/{fileId}** → 204 永久删除(仅限已删除文件,否则 409 `not_deleted`)

### 4.5 实时通知

**GET /v1/events**(WebSocket,握手带 `Authorization: Bearer`)
服务器推:`{"type":"vault.changed","vaultId":"uuid","seq":57}`;每 30 秒发 WebSocket ping。
通知只是「有新东西」的提示,客户端收到后走 changes 接口拉取;断线后客户端指数退避重连(1s 起,上限 60s,加随机抖动),重连成功先全量补拉一次。

## 5. 保留与回收

| 对象 | 规则(服务端可配置) |
|---|---|
| 历史版本 | 每文件保留最近 50 个版本且不早于 90 天;当前版本永远保留 |
| 回收站 | 删除后 30 天自动永久删除 |
| 数据块 | 不再被任何版本引用、且上传超过 24 小时的块由后台任务删除(24 小时宽限期防止误删「已上传未提交」的块) |
| 配额 | 默认每账号 10 GiB,按块密文字节去重计算 |

## 6. 限流

| 范围 | 默认上限 |
|---|---|
| 未认证接口(prelogin / register / login / refresh / recover)每 IP | 30 次/分钟 |
| 登录与恢复每邮箱 | 10 次/分钟 |
| 已认证接口每账号 | 1200 次/分钟 |

超限返回 429 `rate_limited` 与 `Retry-After`。限流计数在单实例内存中;多实例部署时上限按实例生效(文档化的已知边界)。

## 7. 客户端同步引擎行为(规范性要求)

1. **本地状态**:每库一份状态库,记录 路径 → {fileId, version, mtime, size, contentHash, chunks},以及 changes 游标。
2. **检测本地变化**:mtime 或 size 变了才读文件重算 contentHash;摘要相同只更新 mtime。
3. **上传**:切块 → `chunks/check` → 上传缺失块 → `commit`(baseVersion = 本地记录的 version)。
4. **拉取**:按游标拉 changes;对每个版本解密清单,按路径落盘。写文件先写同目录临时文件再原子重命名;下载内容的 contentHash 必须核对。
5. **冲突**(本地有未上传修改,远端版本又前进了):
   - 文本文件(`.md` `.markdown` `.txt`,≤ 2 MiB)且本地保存了上次同步的基线内容 → 三方合并;无重叠修改则合并结果作为新版本提交;
   - 合并失败或非文本 → 远端版本落到原路径,本地版本另存为 `原名 (冲突副本 <设备名> <YYYY-MM-DD HHmm>).扩展名` 并作为新文件上传。**绝不静默丢弃任何一方的内容。**
6. **删除**:本地删除 → 提交墓碑;远端墓碑 → 本地文件移入系统废纸篓(不直接删除)。
7. **改名**:按「旧路径墓碑 + 新路径新文件(复用块,无需重传)」处理。
8. **忽略**:`.DS_Store`、`.typoza/`、`.git/`、`*.tmp`、`~$*`、以及库根目录 `.typozaignore` 中逐行列出的通配模式(`*` `?` `**`,`#` 开头为注释)。
9. **重试**:网络错误与 5xx 按指数退避重试;4xx(除 401 `token_expired` 自动刷新外)不重试,上报错误。
