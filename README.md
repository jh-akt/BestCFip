# Cloudflare 候选 IP 与来源记录

此 Fork 的采集器根据公开来源名单重新实现，原始项目：[joname1/BestCFip](https://github.com/joname1/BestCFip)。

## 运行与输出

GitHub Actions 每四小时运行一次，安排在第 17 分钟，支持手动运行。默认 cron 时区为 UTC，计划时间为 00:17、04:17、08:17、12:17、16:17、20:17 UTC；北京时间/新加坡时间也落在每四小时的第 17 分钟。GitHub 定时任务可能延迟。

采集器只请求配置的公开来源和 Cloudflare 官方地址范围，使用 Python 3.11 标准库。**不扫描、不连接候选 IP，不对候选发出 TCP、TLS、DoH 或网站探活请求。**

| 文件 | 内容 |
| --- | --- |
| [ipv4.txt](ipv4.txt) | 去重后的 IPv4:443#colo=CODE，每行一条，无随机标签和时间头部 |
| [ipv6.txt](ipv6.txt) | 去重后的 [IPv6]:443#colo=CODE，每行一条，无随机标签和时间头部 |
| [candidates.json](candidates.json) | 完整候选、官方匹配网段、来源、采集时间、原始测量字段及本轮来源状态 |

地址仅保留在 [Cloudflare 官方公共代理范围](https://www.cloudflare.com/ips/)内的公网 IP。官方范围核验失败，或本轮没有新的合格候选时，任务失败并保留旧结果。某个来源失败时，保留它之前的有效记录，并在观察记录中标记 `retained=true`；原 `fetched_at` 保持，不能把保留数据误认为本轮新测量。

源网站有明确表头或 JSON 字段时，保存运营商、colo、RTT、丢包、速度、带宽及来源测量时间。字段缺失时不补造。HTML 时间未注明时区时，保留原字符串并标记时区不详。`generated_at` / `fetched_at` 为 UTC，和来源测量时间分别记录。

同一 IP 的多个来源、运营商和 colo 观测会保留。IPv4 国家查询和随机标签已移除；表中的 colo 是原测试网络命中的节点，不表示地址固定在那座机房。

TXT 每行都带 `#colo=`。同一 IP 有多个来源 colo 时去重、排序后用逗号连接，例如 `IP:443#colo=FRA,HKG,LAX`；来源未提供有效三字母代码时为 `#colo=unknown`。不额外请求 trace、不查询候选来补齐 colo。需要纯地址的读取程序应先按 `#` 分隔，取前半部分。

JSON 每个候选的 `colos` 数组提供同样的汇总，缺失时为 `[]`；`observations[].metadata.colo` 保留具体来源、运营商和测量时间对应关系。TXT 汇总也包含标为 retained 的历史有效观测，是否为旧数据应查 JSON。colo 是来源网络当时命中的 CF 节点，无法保证用户本地也命中同一节点。

### Anycast 的证据范围

[Cloudflare 官方说明](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)指出公共代理共享地址范围构成 Anycast 网络。本项目记录官方范围归属，并将 `anycast_per_address_verified` 保持为 `false`；没有为每个 IP 进行多地区宣告或路由实测。

来源如提供 Anycast 声明，会保存为 `metadata.anycast_claim`。该字段是来源声明。属于官方范围、上游称为优选或本轮抓取成功，都不代替当前网络可达性、ECH/DoH 服务兼容性和长期稳定性的验收。

## 数据源

| 标识 | 地址 |
| --- | --- |
| ZXW | https://ip.164746.xyz |
| IPDB / IPDBv6 | https://ipdb.api.030101.xyz/?type=bestcf / ?type=bestcfv6 |
| WeTest / WeTestV6 | https://www.wetest.vip/page/cloudflare/address_v4.html / address_v6.html |
| CFYes | https://cf.090227.xyz/CloudFlareYes |
| HaoGG | https://ip.haogege.xyz |
| VPS | https://vps789.com/openApi/cfIpApi |
| CMLiuss / CMLiussv6 | https://addressesapi.090227.xyz/ct / cmcc-ipv6 |
| FaaS | https://raw.githubusercontent.com/xingpingcn/enhanced-FaaS-in-China/refs/heads/main/Cf.json |

部分来源提供第三方前置地址或旧测量数据。范围外地址会被排除；来源时间与抓取时间单独记录。动态 JavaScript 页面未暴露支持的地址数据时，该来源记为失败，不执行页面脚本。

Uouin 已于 2026-10-08 停止采集：其发布的测量时间为 2024-04-09。既有 JSON 中来自 Uouin 的观测在下一次成功采集时清除，仅由该来源提供的地址也会移除；其他有效来源提供的同一地址可以保留。退役来源不走失败保留逻辑。其余可见测量时间的来源在此次核对中为 2026-10-08；未提供测量时间的来源继续明确留空。

## 工作流

1. `collect`：只读仓库权限，checkout 不持久保存认证凭据；先运行离线解析/失败保留测试，再采集并生成校验后的三个结果文件。
2. `publish`：独立任务，只负责取得本轮结果并提交；需要该仓库的 contents write 权限。

只有采集和测试成功时才进入提交任务。没有向采集器传递仓库写入令牌或配置仓库 Secrets。结果 artifact 保留七天；仓库 Git 历史可追溯各轮变化。

手动执行：进入 [Actions](https://github.com/jh-akt/BestCFip/actions)，选择 **Collect Cloudflare candidates** → **Run workflow**。

本地离线测试：

```sh
python3 -m unittest -v test_collector
```

运行采集器会向上述公开来源发送 HTTPS 请求：

```sh
python3 collects.py
```

上游随机国家标签已替换为来自来源观测的 colo 标签。首次运行若某个 IP 家族没有新数据，原列表内仍属于官方范围的地址会以 `legacy-import` 标记保留；来源未知的旧地址不会被标成新采集。
