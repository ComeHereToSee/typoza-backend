-- Typoza 云端保存服务初始表结构。
-- 零知识:除邮箱与时间戳外,业务内容全是客户端密文或不透明 ID;encrypted_* 字段原样存客户端给的 base64url 文本。

-- 账号。auth_hash = Argon2id(authKey, auth_salt),authKey 本身由客户端从主密码派生,服务器从不见主密码。
CREATE TABLE users (
    id                             uuid        PRIMARY KEY,
    email                          text        NOT NULL UNIQUE, -- 已 trim + 小写
    kdf                            jsonb       NOT NULL,        -- 客户端主密码 KDF 参数与盐,prelogin 原样回传
    auth_hash                      bytea       NOT NULL,
    auth_salt                      bytea       NOT NULL,
    encrypted_account_key          text        NOT NULL,
    recovery_auth_hash             bytea       NOT NULL,
    recovery_auth_salt             bytea       NOT NULL,
    recovery_encrypted_account_key text        NOT NULL,
    totp_secret_enc                bytea,                       -- 已启用的 TOTP 密钥(服务端数据密钥加密)
    totp_pending_enc               bytea,                       -- setup 后、enable 前的待确认密钥
    totp_enabled                   boolean     NOT NULL DEFAULT false,
    totp_last_step                 bigint      NOT NULL DEFAULT 0, -- 最近一次成功的时间步,防同一验证码重放
    quota_bytes                    bigint      NOT NULL,
    used_bytes                     bigint      NOT NULL DEFAULT 0, -- 块密文去重后的总字节
    created_at                     timestamptz NOT NULL DEFAULT now(),
    updated_at                     timestamptz NOT NULL DEFAULT now()
);

-- 设备 = 一条登录会话的归属。revoked_at 非空表示已登出或被吊销,其访问令牌立即失效。
CREATE TABLE devices (
    id           uuid        PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text        NOT NULL,
    platform     text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at   timestamptz
);
CREATE INDEX devices_user_idx ON devices (user_id);

-- 刷新令牌只存 SHA-256 摘要。used_at 非空 = 已轮换;已轮换的令牌再次出现即判定被盗用。
CREATE TABLE refresh_tokens (
    id         uuid        PRIMARY KEY,
    device_id  uuid        NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    family_id  uuid        NOT NULL, -- 一次登录产生的令牌链
    token_hash bytea       NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_device_idx ON refresh_tokens (device_id);
CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens (expires_at);

-- 恢复流程令牌:recover/begin 发放,10 分钟有效、一次性。
CREATE TABLE recovery_tokens (
    token_hash bytea       PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX recovery_tokens_user_idx ON recovery_tokens (user_id);

-- 库(云同步文件夹)。id 由客户端生成;seq 是库内单调递增的变更序号,提交时在事务内 +1。
CREATE TABLE vaults (
    id             uuid        PRIMARY KEY,
    user_id        uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    encrypted_name text        NOT NULL,
    seq            bigint      NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vaults_user_idx ON vaults (user_id);

-- 文件当前状态(head)。changes 按 head_seq 增量拉取。
CREATE TABLE files (
    vault_id     uuid        NOT NULL REFERENCES vaults (id) ON DELETE CASCADE,
    id           uuid        NOT NULL,
    head_version bigint      NOT NULL,
    head_seq     bigint      NOT NULL,
    deleted      boolean     NOT NULL,
    deleted_at   timestamptz,
    PRIMARY KEY (vault_id, id)
);
CREATE INDEX files_vault_seq_idx ON files (vault_id, head_seq);
CREATE INDEX files_trash_idx ON files (deleted_at) WHERE deleted;

-- 文件历史版本。manifest 是客户端加密的清单;chunks 是明文块 ID 列表,用于校验块齐全与回收时判断引用。
CREATE TABLE file_versions (
    vault_id   uuid        NOT NULL,
    file_id    uuid        NOT NULL,
    version    bigint      NOT NULL,
    seq        bigint      NOT NULL,
    manifest   bytea       NOT NULL,
    chunks     text[]      NOT NULL,
    size       bigint      NOT NULL,
    deleted    boolean     NOT NULL,
    device_id  uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (vault_id, file_id, version),
    FOREIGN KEY (vault_id, file_id) REFERENCES files (vault_id, id) ON DELETE CASCADE
);
CREATE INDEX file_versions_chunks_idx ON file_versions USING gin (chunks);

-- 数据块。按账号隔离;object_key 每次上传唯一,块回收与并发重传不会互相删掉对方的对象。
CREATE TABLE chunks (
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    id         text        NOT NULL,
    size       bigint      NOT NULL,
    object_key text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id)
);
CREATE INDEX chunks_created_idx ON chunks (created_at);

-- 安全审计:登录成功/失败、改密、恢复、设备吊销、TOTP 变更等。账号删除时一并删除。
CREATE TABLE audit_events (
    id         bigserial   PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    device_id  uuid,
    kind       text        NOT NULL,
    ip         text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_user_idx ON audit_events (user_id, created_at);
