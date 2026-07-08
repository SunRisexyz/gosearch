# gosearch

gosearch 是一个用 Go 编写的 Web 目录/文件发现工具，功能对标 dirsearch，并针对高并发、代理、递归、模糊测试、断点续扫、软 404 过滤、指纹识别、风险分级和结构化报告输出做了工程化支持。

它适合用于渗透测试前期信息收集、认证态目录扫描、批量资产探测和敏感路径发现。

## 特性概览

- 目录/文件扫描：支持自定义字典、扩展名组合、递归扫描和 `{dir}` fuzz 占位符。
- 高并发扫描：支持线程数、CPU 核心数、固定延迟、随机延迟和自适应限速。
- 代理支持：HTTP 代理、SOCKS5 代理、代理认证，代理失败可自动直连兜底。
- 请求上下文：支持自定义 Header、Cookie、headers 文件和 Burp Raw Request 复用。
- 指纹识别：基于 Header、Title、Body、Path、Favicon Hash 识别 Web 框架、中间件、CMS 和敏感组件。
- 自适应字典：命中指纹后自动追加技术栈相关高价值路径。
- 软 404 过滤：通过随机不存在路径建立基线，过滤假 200、统一错误页等误报。
- 风险分级：按敏感路径、指纹、状态码自动标记风险等级、分数和原因。
- 路径发现：支持从 `robots.txt` 和 `sitemap.xml` 自动导入路径。
- 备份变体：命中路径后自动生成 `.bak`、`.old`、`~`、`.zip` 等常见备份文件变体。
- 多方法探测：命中后可追加 `HEAD`、`OPTIONS` 等方法探测并记录 `Allow` 头。
- 断点续扫：支持 resume 文件跳过已完成 URL，并保留已命中结果。
- 报告输出：支持 txt、csv、json、md，结果按 host 分组并按风险优先级排序。

## 构建

```bash
# 准备依赖
go mod download

# Linux/WSL
./build.sh

# Windows
.\build.bat

# 或直接构建
go build ./...
```

Go 版本要求：`>= 1.21`。

## 快速开始

```bash
# 单目标扫描
gosearch scan -u http://example.com -w dict.txt -t 50

# 批量目标 + 自定义字典
gosearch scan -l targets.txt -w dict.txt -t 30 --exclude-status 404,500

# 扩展名组合
gosearch scan -u http://example.com -w dict.txt -e php,asp,aspx,html

# 递归 + fuzz
gosearch scan -u https://example.com -w dict.txt -r --max-depth 3 --fuzz

# 输出报告
gosearch scan -u http://example.com -w dict.txt -o result.json
gosearch scan -u http://example.com -w dict.txt -o csv
```

## 实用功能示例

### 指纹识别与风险排序

```bash
gosearch scan -u https://example.com -w dict.txt --fingerprint --risk-score

# 只保留高危及以上结果
gosearch scan -u https://example.com -w dict.txt --risk-score --min-risk high
```

指纹结果会写入报告字段 `fingerprints`，风险信息会写入 `risk_level`、`risk_score`、`risk_reasons` 和 `tags`。

### 指纹联动字典

```bash
gosearch scan -u https://example.com -w dict.txt --adaptive-wordlist
```

命中 WordPress、Tomcat、Swagger、Spring Boot Actuator、Jenkins、Grafana、Nacos 等指纹后，会自动追加对应技术栈的高价值路径。

### 软 404 过滤

```bash
gosearch scan -u https://example.com -w dict.txt --soft-404
gosearch scan -u https://example.com -w dict.txt --soft-404 --soft-404-samples 3
```

扫描前会请求随机不存在路径建立基线。若命中结果与基线状态码一致、大小相近、标题一致，则会被判定为软 404 并过滤。

### 自定义 Header 和 Cookie

```bash
gosearch scan -u https://example.com -w dict.txt \
  -H "Authorization: Bearer <token>" \
  -H "X-Forwarded-For: 127.0.0.1" \
  --cookie "PHPSESSID=abc; token=xyz"
```

也可以从文件加载请求头：

```bash
gosearch scan -u https://example.com -w dict.txt --headers-file headers.txt
```

`headers.txt` 示例：

```http
Authorization: Bearer <token>
X-Forwarded-For: 127.0.0.1
User-Agent: Mozilla/5.0
```

### Burp Raw Request 复用

```bash
gosearch scan --raw-request request.txt -w dict.txt --raw-scheme https
```

Raw Request 会复用 method、Host、Header、Cookie 和 body。若没有传 `-u/-l`，会从 Raw Request 的 Host 自动推导目标。命令行传入的 `-u/-l`、`-X`、`-H`、`--cookie` 优先级更高。

### robots.txt / sitemap.xml 导入

```bash
gosearch scan -u https://example.com -w dict.txt --discover
gosearch scan -u https://example.com -w dict.txt --discover --discover-max 500
```

会自动导入同 host 下的 `Allow`、`Disallow`、`Sitemap` 和 sitemap `<loc>` 路径。发现路径按原样请求，不会被扩展名规则二次改写。

### 备份文件变体

```bash
gosearch scan -u https://example.com -w dict.txt --backup-variants
gosearch scan -u https://example.com -w dict.txt --backup-variants --backup-variant-max 20
```

命中 `config.php` 后会尝试：

```text
config.php.bak
config.php.backup
config.php.old
config.php~
config.bak.php
```

命中目录时会尝试：

```text
admin.zip
admin.tar.gz
admin.7z
admin.bak
```

备份变体命中后不会继续生成二级变体，避免无限扩散。

### 自适应限速

```bash
gosearch scan -u https://example.com -w dict.txt --adaptive-throttle
gosearch scan -u https://example.com -w dict.txt --adaptive-throttle --throttle-step 200 --throttle-max-delay 5000
```

遇到 `429`、`502`、`503`、`504` 或请求失败时会动态增加延迟；健康响应会逐步降低延迟。

### 多方法探测

```bash
gosearch scan -u https://example.com -w dict.txt --probe-methods HEAD,OPTIONS
```

主扫描命中后，会对同一 URL 追加指定方法探测，并记录状态码、响应大小、耗时、`Allow` 头和跳转地址。

### 断点续扫

```bash
gosearch scan -u https://example.com -w dict.txt --resume
gosearch scan -u https://example.com -w dict.txt --resume-file report/resume/example.jsonl
```

`--resume` 会记录已完成 URL，再次运行时跳过已完成请求，并保留之前已经命中的结果。

## 主要参数

- 目标与字典：`-u/--url`、`-l/--list`、`-w/--wordlist`、`--default-wordlist`
- 扫描策略：`-e/--extensions`、`-F/--fuzz`、`-G/--fuzz-dict`、`-r/--recursive`、`--max-depth`
- 请求上下文：`-H/--header`、`--cookie`、`--headers-file`、`--raw-request`、`--raw-scheme`
- 请求控制：`-X/--method`、`--probe-methods`、`-T/--timeout`、`--connect-timeout`、`--response-header-timeout`、`--max-body-bytes`
- 代理：`-p/--proxy`、`-5/--socks5`、`-a/--proxy-auth`、`--no-proxy-fallback`
- 重试与 TLS：`-y/--retry`、`-R/--follow-redirects`、`-M/--max-redirects`、`-k/--insecure`
- 过滤：`--status-codes`、`-E/--exclude-status`、`-S/--exclude-size`、`-C/--exclude-content`、`--soft-404`
- 增强发现：`--fingerprint`、`--fingerprint-rules`、`--adaptive-wordlist`、`--discover`、`--backup-variants`
- 风险分析：`--risk-score`、`--min-risk`
- 速率控制：`-t/--threads`、`-d/--delay`、`--random-delay`、`--adaptive-throttle`、`--throttle-step`、`--throttle-max-delay`、`-P/--max-procs`
- 输出与调试：`-o/--output`、`-q/--quiet`、`-D/--debug`

## 报告与去重

- 终端输出按 host 分组，并对同 host 下状态码 + 响应大小的重复结果只显示第一次命中。
- 报告路径：`report/<host>/_yy-mm-dd_hh-mm-ss.<ext>`。
- 支持格式：txt、csv、json、md。
- JSON 报告包含 `risk_summary`、`top_findings`、`results` 和 `formatted`。
- 开启风险评分后，报告会按 `critical -> high -> medium -> low -> info` 排序。
- 开启指纹识别、多方法探测后，报告会包含 `fingerprints` 和 `method_probes`。

## 字典初始化

使用默认字典时：

```bash
gosearch scan -u http://example.com --default-wordlist
```

首次运行会在当前目录初始化：

- `dict/dict.txt`：默认字典，可自行编辑。
- `report/`：默认报告目录。

初始化后，后续扫描可直接使用配置中的默认字典路径。

## 典型组合

```bash
# 认证态扫描 + 指纹 + 风险排序
gosearch scan -u https://example.com -w dict.txt \
  -H "Authorization: Bearer <token>" \
  --fingerprint --risk-score --min-risk medium
```

```bash
# 实战增强发现
gosearch scan -u https://example.com -w dict.txt \
  --discover --soft-404 --backup-variants --adaptive-wordlist
```

```bash
# Burp 请求复用 + 多方法探测 + 自适应限速
gosearch scan --raw-request request.txt -w dict.txt \
  --raw-scheme https \
  --probe-methods HEAD,OPTIONS \
  --adaptive-throttle
```

## 与 dirsearch 的主要差异

- 更强调 Go 并发扫描、任务恢复和工程化输出。
- 支持指纹识别、风险分级、Top Findings 和结构化安全报告字段。
- 支持认证态扫描、Raw Request 复用和复杂请求上下文。
- 支持 robots/sitemap 路径导入、指纹联动字典和备份文件变体。
- 支持软 404 基线过滤和自适应限速，更适合真实目标扫描。

## 调试与排障

- 使用 `--debug` 查看请求错误、代理降级、软 404 过滤、自适应字典、备份变体和限速变化。
- 代理问题：确认 `--proxy`、`--socks5`、`--proxy-auth` 格式正确。
- 输出不全：检查 `--status-codes`、`--exclude-*`、`--soft-404`、`--min-risk` 和去重规则。
- Raw Request 失败：确认请求中存在 `Host` 头；相对路径请求需要设置 `--raw-scheme http|https`。
- 软 404 误过滤：可调大/调小 `--soft-404-size-tolerance`，或暂时关闭 `--soft-404`。
