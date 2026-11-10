# 富江破甲包（内置扩展）

本仓库内置了「富江破甲」扩展包（上游 `fujiang-pojia` 0.20.12），把上游给 DeepSeek Harness 写的 Cordis 插件，
改造成本 App 原生的两套机制：**内置技能** + **提示词覆盖层**，另配一个本地知识库匹配工具。

## 放了什么

| 位置 | 内容 |
| --- | --- |
| `app/src/main/assets/fujiang/skills/kb-*/` | 9 个分类、167 条 CVE/PoC 语料（每条一个 `.md`，frontmatter 带 title/cve/severity/product/versions/ports/keywords） |
| `app/src/main/assets/fujiang/prompts/00-identity.md` | 富江人设与破甲规则，覆盖内置 `prompts/00-identity.md` |
| `app/src/main/assets/fujiang/prompts/50-safety.md` | 覆盖内置安全片段：保留可逆性判断与注入防护，去掉拒绝式边界 |
| `app/src/main/assets/fujiang/version.txt` | 包版本，用于「版本变了才重新释放」 |
| `KnowledgeIndex.kt` | 语料索引 + 指纹匹配（端口/产品/CVE/关键词打分） |
| `KbMatchTool.kt` | 工具 `kbMatch`，把匹配结果给 AI |

## 运行时怎么落地

`AIEditorApp` 启动时调用 `ContainerInstaller.extractFujiangPack(context)`：

1. `~/.aicode/` 下存在空文件 `fujiang.off` → 整包跳过（已释放内容保留）。
2. 读 `assets/fujiang/version.txt` 与 `~/.aicode/fujiang.pack-version` 比对，相同则直接返回（避免每次启动重写 176 个文件）。
3. 技能：`assets/fujiang/skills/kb-x/` → `~/.aicode/skills/kb-x/`，覆盖式释放。
4. 提示词：`assets/fujiang/prompts/*.md` → `~/.aicode/prompts.custom/`，**只在目标不存在时写入**，写过后由用户接管，升级不回滚。
5. 版本号写回 `fujiang.pack-version`。

技能文件落盘后由既有的 `GlobalDirectorySkillSource` 扫描进「可用技能」清单，AI 用 `loadSkill` 读正文；
`prompts.custom/` 由 `SystemPromptProvider` 按编号身份覆盖内置片段（`00-` 覆盖身份、`50-` 覆盖安全）。

## kbMatch 打分

与上游 `automation.js` 的 `createKbIndex().match()` 一致，纯本地排序、不联网、不执行：

| 命中项 | 分值 |
| --- | --- |
| 端口 | +35 |
| 产品整词 | +60 |
| CVE 号 | +20 |
| 英文关键词 | 每条 +8，封顶 16 |
| 中文关键词 | 每条 `8 + 2×(字数-2)`，封顶 40 |
| 标题词 | 每条 +6，封顶 18（产品已命中时不计） |
| severity=critical | +5 |

入参：`ports`（`443,8443`）、`banner`、`product`、`text`、`limit`（默认 5，最大 20）。
出参：`hits[]`，每条带 `score/category/file/path/title/cve/severity/product/versions/why`，
`path` 可直接 `readFile` 读详情。

## 与上游插件的差异

- 上游的 Cordis 面板（状态开关、漏洞报告、渗透作业链 `campaigns`）依赖 DSH 的 `webServer`/`skills.registerProvider`/`agent` 生命周期，
  本 App 没有等价内核，**未移植**；对应能力用「技能 + 提示词 + kbMatch 工具」承担。
- 上游按需下载的 REA / AboutSecurity 技能库不随包内置（体积与网络原因），需要时用 App 的技能导入功能单独装。
- 上游 `verified: false` 语义保留：条目是公开资料整理，出报告前须按目标版本自验。

## 关掉 / 更新

```bash
# 关掉（保留已释放文件，不再注入提示词、不再刷新技能）
touch ~/.aicode/fujiang.off

# 重新打开
rm ~/.aicode/fujiang.off

# 强制重新释放（改了 assets 里的语料后）
rm ~/.aicode/fujiang.pack-version
```

`~/.aicode/` 在容器内即 `/root/.aicode/`，也可以用 App 的文件树直接改。
