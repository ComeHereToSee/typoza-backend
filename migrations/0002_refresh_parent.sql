-- 刷新令牌记下它是由哪个令牌换出来的:轮换响应在网络上丢失时,客户端会拿旧令牌重试,
-- 服务端据此判断「换出的新令牌从没被用过」,在宽限期内重新签发而不是当作重放(协议 §3.1)。
ALTER TABLE refresh_tokens ADD COLUMN parent_id uuid;
CREATE INDEX refresh_tokens_parent_idx ON refresh_tokens (parent_id) WHERE parent_id IS NOT NULL;
