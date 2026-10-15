#!/usr/bin/env bash
# 用法:ci/step.sh <步骤名> <命令...>
# 命令输出同时写入 $CI_OUT/<步骤名>.log,并在 $CI_OUT/steps.tsv 追加「步骤名 退出码 耗时秒」。
# 仓库是私有的、本地只有 SSH 推送权限读不到 Actions 日志,所以日志要落盘再由 publish.sh 回传。
set -uo pipefail
name="$1"; shift
out="${CI_OUT:?CI_OUT 未设置}"
mkdir -p "$out"
start=$(date +%s)
"$@" 2>&1 | tee "$out/$name.log"
code=${PIPESTATUS[0]}
printf '%s\t%s\t%s\n' "$name" "$code" "$(( $(date +%s) - start ))" >> "$out/steps.tsv"
exit "$code"
