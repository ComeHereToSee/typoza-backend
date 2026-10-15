# 服务端实现踩坑与约定

> 来源:2026-10-16 服务端首版实现。只记会再次踩到的坑。

## 本机环境

- 本机 `~/go/pkg/mod`、`~/Library/Caches/go-build` 属主是 root、不可写。`go mod tidy` / `go mod download` 需指定可写目录:
  `GOPATH=~/Documents/typoza/localClaude/gopath GOMODCACHE=~/Documents/typoza/localClaude/gomodcache GOCACHE=~/Documents/typoza/localClaude/gocache`。
- 本机不编译、不跑测试(用户指令),只 `gofmt` 与 `go mod tidy`;依赖 API 一律去上面的 GOMODCACHE 读源码核实。

## gosec(CI 固定 v2.29.0,`-severity medium`)

- **G117**:`json.Marshal` / `Encoder.Encode` 的实参静态类型里有名为 accessToken、refreshToken、authKey、secret 等字段即报。
  协议出参本就要下发令牌,统一经 `writeJSON(w, status, v any)` 编码(实参是 `any`,规则看不到字段)。
- **G115**:整数窄化/符号转换(如 `int64 → uint64`)是 High。先判范围再转,并在该行写 `// #nosec G115 -- 理由`。
- **G505 / G401**:TOTP 必须用 HMAC-SHA1(RFC 6238),在 import 行与 `sha1.New` 处写 `#nosec` 并给理由。
- **G101**:名字含 token/secret/pass/cred 的常量若值是高熵字符串会报;常量名避开这些词(如 `RefreshPrefix`)。
- **G703 等污点规则**:`os.Getenv` 被当作污点源;配置读取用 `os.LookupEnv`。磁盘对象存储用 `os.Root`,天然防穿越。
- **G118**:带 ctx / *http.Request 参数的函数里不要 `go` 一个用 `context.Background()` 的协程;后台任务用 `context.WithoutCancel(ctx)` 派生,并把 cancel 存进结构体字段、在 Close 里调用。

## pgx v5

- Go `string` 传给 uuid 列可以(字符串参数走文本格式);`[]string` 传给 `uuid[]` 不行 —— 用 `$1::text[]` 再在 SQL 里 `::uuid`。
- 扫描 uuid 到 `string` 可以;为直观起见 SELECT 里统一写 `id::text`。
- jsonb 读回来的文本会被 PostgreSQL 规范化(键按长度排序、带空格);要回传给客户端的 JSON 先反序列化到结构体再编码。
- 表达式里的参数(如 `$3 - interval '1 minute'`、`CASE WHEN $5`)显式加类型转换,避免类型推断歧义。
- 会话级 advisory lock 绑定连接:迁移用独立 `pgx.Connect` 连接;从连接池借的连接若解锁失败要 `Hijack().Close()`,不能把持锁连接还回池。

## HTTP

- `coder/websocket` 通过 `Unwrap()` 找 Hijacker:自定义 ResponseWriter 包装必须实现 `Unwrap() http.ResponseWriter`。
- `ServeMux` 把 `r.Pattern` 写在它收到的那份请求上;外层中间件若做过 `r.WithContext`,看不到 Pattern。按路由聚合指标要在注册路由时把模式记进请求上下文里的可变结构。
- 服务端不要设 `ReadTimeout`/`WriteTimeout`,会误杀 WebSocket 与大块传输;用 `ReadHeaderTimeout` + 请求体上限。

## 并发正确性(数据不丢的关键)

- 同一库的提交靠库行 `FOR UPDATE` 串行,seq 可见顺序 = 分配顺序。
- 块回收与提交:提交对块行 `FOR SHARE`;回收先 `FOR UPDATE SKIP LOCKED` 选候选,再用新语句(新快照)二次确认无引用后删除;先删记录、提交后再删对象。
- 块对象键带每次上传唯一的随机后缀,回收与并发重传永远操作不同对象。
