# 5字母 .com 域名低速查询脚本

`domain_scan_safe.py` 用于**低频率**遍历 5 字母 `.com` 域名，并通过 RDAP 判断是否可能可注册。

## 为什么更不容易被误认为攻击

- 默认每次请求随机延迟 `1.2~2.5` 秒。
- 遇到 `429/5xx` 会指数退避重试。
- 建议在 `User-Agent` 中携带可联系邮箱。
- 支持断点续跑，避免短时间重复扫同一批。

> 注意：任何自动化查询都可能触发风控，请先阅读并遵守注册局/RDAP 服务条款。

## 使用

```bash
python domain_scan_safe.py \
  --max-queries 200 \
  --resume \
  --user-agent "safe-domain-checker/1.0 (contact: me@yourdomain.com)"
```

输出：
- `results.csv`：查询结果
- `state.json`：断点进度

## 常用参数

- `--max-queries`：本次最多查多少个（默认 100）
- `--min-delay / --max-delay`：请求间隔（默认 1.2~2.5 秒）
- `--resume`：从 `state.json` 继续
- `--start-after abcde`：从某个标签之后开始
- `--output custom.csv`：输出文件

## 结果解读

- `registered`：RDAP 有记录（通常已注册）
- `available`：RDAP 404（通常未注册）
- `uncertain`：网络/限流/异常，需复查

最终是否可注册，以你所用注册商的实时下单页为准。
