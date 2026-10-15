#!/usr/bin/env bash
# 用法:ci/publish.sh <job 名> <job 状态>
# 把 $CI_OUT 里的日志与产物强推到孤儿分支 ci/<job>(单提交,不累积历史),本地用 git fetch 读取。
set -euo pipefail
job="$1"; status="$2"
out="${CI_OUT:?CI_OUT 未设置}"
mkdir -p "$out"
dir=$(mktemp -d)
cp -R "$out"/. "$dir"/
cat > "$dir/SUMMARY.md" <<SUM
job: $job
status: $status
sha: $GITHUB_SHA
ref: $GITHUB_REF_NAME
run: $GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID
time: $(date -u +%FT%TZ)
SUM
cd "$dir"
git init -q
git checkout -q --orphan "ci/$job"
git add -A
git -c user.name="typoza-ci" -c user.email="ci@typoza.invalid" commit -qm "ci($job): $status @ ${GITHUB_SHA:0:7}"
git push -qf "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" "HEAD:refs/heads/ci/$job"
