# gosearch

gosearch 是一个用 Go 编写的目录/文件暴力扫描工具，功能对标 dirsearch，并针对高并发、代理、递归、模糊测试、过滤和报告输出做了工程化支持。

## 特性概览
- 目录/文件扫描，支持 `-e` 扩展名组合、`--force-extensions` 全量追加。
- 递归扫描 (`-r --max-depth`) 与模糊占位符 `{dir}` (`--fuzz --fuzz-dict`)。
- 并发与速率控制：`-t` 线程、`--delay`/`--random-delay`、`--max-procs`。
- 代理：HTTP `--proxy`、SOCKS5 `--socks5`、`--proxy-auth`，失败自动直连兜底。
- 请求健壮性：`--retry`、`--follow-redirects --max-redirects`、`--insecure` 跳过证书验证。
- 过滤与去重：`--status-codes` 仅显示，`--exclude-status/size/content` 过滤，终端/报告按 host+状态码+大小去重，仅输出首个命中。
- 输出：终端彩色单行进度，结果按 host 分组；报告支持 txt/csv/json/md，路径按 `report/<host>/_yy-mm-dd_hh-mm-ss.ext`。
- 配置：`config.yml` 默认字典/线程/过滤/输出后缀；内置小型默认字典、UA 池。
- CLI：基于 Cobra，常用参数有短选项（`-u/-l/-w/-e/-t/-r/-m/-p/-R/-E/-S/-C/-q/-d/-D/-X` 等）。

## 快速开始
```bash
# 准备依赖
go mod download

# 单目标扫描
gosearch scan -u http://example.com --default-wordlist -e php,asp,aspx -t 50

# 批量目标 + 自定义字典
gosearch scan -l targets.txt -w dict.txt -t 30 --exclude-status 404,500

# 递归 + fuzz
gosearch scan -u https://example.com -w dict.txt -r --max-depth 3 --fuzz

# 指定输出格式
gosearch scan -u http://example.com -w dict.txt -o result.json
gosearch scan -u http://example.com -w dict.txt -o csv
```

## 主要参数
- 目标与字典：`-u/--url`、`-l/--list`、`-w/--wordlist`、`--default-wordlist`
- 扫描：`-e/--extensions`、`-F/--fuzz`、`-G/--fuzz-dict`、`-r/--recursive`、`-m/--max-depth`
- 并发与速率：`-t/--threads`、`-d/--delay`、`--random-delay`、`-P/--max-procs`
- 代理：`-p/--proxy`、`-5/--socks5`、`-a/--proxy-auth`
- 请求控制：`-X/--method`、`-T/--timeout`、`-k/--insecure`、`-y/--retry`、`-R/--follow-redirects`、`-M/--max-redirects`
- 过滤/输出：`--status-codes`、`-E/--exclude-status`、`-S/--exclude-size`、`-C/--exclude-content`、`-q/--quiet`、`-o/--output`
- 调试：`-D/--debug`（打印请求/响应调试信息）

## 报告与去重
- 终端输出按 host 分组，并对同 host 下状态码+响应大小的重复结果只显示第一次命中。
- 报告路径：`report/<host>/_yy-mm-dd_hh-mm-ss.<ext>`，支持 txt/csv/json/md；csv/json 内含过滤后的结果。

## 构建
```bash
# Linux/WSL
./build.sh

# Windows
.\build.bat

# 或直接
go build ./...
```
Go 版本要求：>= 1.21。

## 典型使用示例
1) 单目标 + 扩展名：
```
gosearch scan -u http://127.0.0.1 --default-wordlist -e php,aspx,html -t 50
```
2) 批量目标 + 输出 CSV：
```
gosearch scan -l targets.txt -w dict.txt -o csv --status-codes 200,301,302,403
```
3) 递归 + fuzz：
```
gosearch scan -u https://example.com -w dict.txt -r --max-depth 3 --fuzz --random-delay
```

## 与 dirsearch 的主要差异
- 默认启用按 host+状态码+响应大小的去重，只保留首个命中；可通过字典/状态码调整输出。
- 报告分 host 存储，路径规则固定（不与原版完全一致）。
- 部分高级特性（例如自动 404 基线、字典自动优化）未实现。

## 调试与排障
- `--debug` 查看请求/响应、代理降级等详细信息。
- 代理问题：确认 `--proxy`/`--socks5` 格式正确；如代理失败会自动直连（debug 有提示）。
- 输出不全：检查 `--status-codes` / `--exclude-*` / 去重规则；响应体包含 `--exclude-content` 关键词会被过滤。

