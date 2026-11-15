# 富江破甲

「富江破甲」是一套内置的安全研究辅助能力：本地 CVE/PoC 知识库、漏洞报告、渗透作业链。它不联网、不上传任何数据，全部内容都在手机本地（容器内即 `/root/.aicode/`）。

入口在 **设置 → 富江破甲**，页面分三块：**漏洞报告**、**知识库**、**渗透作业链**。右上角刷新按钮会重新读取磁盘，AI 刚写进去的内容立刻可见。

## 漏洞报告

AI 在确认漏洞后用 `findingUpsert` 写入这里，每条记录包含等级、目标、证据、修复建议等字段。

- 新增必须同时提供 **目标** 与 **证据**，没有证据的条目工具会拒绝写入。
- 点击条目查看完整字段；弹窗里可以删除。
- 数据文件：`~/.aicode/fujiang/vuln-report/findings.json`，可以直接用文件工具查看或备份。

等级分 critical / high / medium / low / info，建议按实际验证结果填写，工具里 `verified` 表示是否已实测。

## 知识库

内置 9 个分类、167 条 CVE/PoC 条目，App 首次启动时自动释放到 `~/.aicode/skills/kb-*`，在页面里按分类列出。

- 点条目查看完整 PoC：利用条件、请求、判定标准。
- 条目是公开资料整理（`verified: false`），出报告前要按目标版本自验。
- AI 侧对应 `kbMatch`：给端口、banner、响应头、产品名或描述文本，按分数返回候选条目。
- 想加自己的条目：在对应 `kb-*` 目录下新增一个 `.md`，frontmatter 写 `title / cve / severity / product / versions / ports / keywords`，页面刷新即可看到。

页面里的条目只读；要改内容请直接编辑 `~/.aicode/skills/` 下的文件。

## 渗透作业链

一个任务的台账：授权范围、资产、每一步命令与结论、PoC 尝试结果、当前阶段。

- 阶段链固定为 `recon → fingerprint → match → verify → exploit → lateral → report`，只能往前推进。
- 资产 host 必须落在任务授权范围内才允许写入，范围外的目标会被工具拒绝。
- 数据文件：`~/.aicode/fujiang/vuln-report/campaigns.json`。
- AI 侧工具：`campaignUpsert`（建任务、记资产、记步骤、记尝试、推进阶段、收尾、删除）、`pipelineNext`（读取下一步与候选条目）。

## AI 会用到哪些工具

| 工具 | 作用 |
| --- | --- |
| `kbMatch` | 按端口 / banner / 响应头 / 产品名 / 描述匹配本地漏洞条目 |
| `skillSearch` | 按关键词检索本地技能库，可带回正文 |
| `findingUpsert` | 写入 / 更新 / 删除漏洞报告条目 |
| `campaignUpsert` | 创建与管理渗透作业链任务 |
| `pipelineNext` | 读取任务下一步、阶段进度与候选漏洞条目 |

这些工具都是本地读写，不发起网络请求。

## 关闭与重置

```bash
# 整包关掉：不再释放知识库与提示词，已释放的文件保留
touch ~/.aicode/fujiang.off

# 重新打开
rm ~/.aicode/fujiang.off

# 强制重新释放知识库与提示词（会覆盖用户没改过的提示词片段）
rm ~/.aicode/fujiang.pack-version
```

自定义提示词放在 `~/.aicode/prompts.custom/`，改过的片段升级时不会被覆盖。

## 常见问题

**漏洞报告一直是空的？** 需要 AI 调用 `findingUpsert` 写入；也可以直接编辑 `findings.json` 后点刷新。

**知识库为空？** 确认 `~/.aicode/skills/` 下有 `kb-*` 目录；没有就删掉 `~/.aicode/fujiang.pack-version` 后重启 App 重新释放。存在 `fujiang.off` 时整包不会释放。

**作业链记不了资产？** 目标不在任务的 `scope` 里。重新建任务时把域名、IP 或 CIDR 写全，排除项用 `!` 前缀。
