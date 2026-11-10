package com.aicode.feature.agent.domain.tool.skill

import com.aicode.core.util.FileLogger
import com.aicode.feature.agent.domain.skill.KnowledgeIndex
import com.aicode.feature.agent.domain.tool.AgentTool
import com.aicode.feature.agent.domain.tool.ParameterType
import com.aicode.feature.agent.domain.tool.ToolCapability
import com.aicode.feature.agent.domain.tool.ToolParameter
import com.aicode.feature.agent.domain.tool.ToolResult
import com.aicode.feature.workspace.domain.FileAccessProvider
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.jsonPrimitive
import javax.inject.Inject

/**
 * 指纹 → CVE/PoC 知识库候选条目。给端口、banner、产品名或任意描述文本，返回按分数排序的候选，
 * 每条带 `category` / `file` / `path`（可直接用 readFile 读详情）与命中理由 `why`。
 *
 * 只做本地匹配，不联网、不执行任何东西；分数只是排序依据，不等于条目已在目标上验证。
 */
class KbMatchTool @Inject constructor(
    private val fileAccess: FileAccessProvider
) : AgentTool() {
    private companion object {
        const val TAG = "KbMatchTool"
        const val DEFAULT_LIMIT = 5
    }

    override val name = "kbMatch"
    override val capabilities = setOf(ToolCapability.READ_AGENT_CONFIG)
    override val description =
        "在本地 CVE/PoC 知识库（~/.aicode/skills/kb-*）里按端口、banner、产品名或描述文本匹配漏洞条目，" +
            "返回候选条目与命中理由。拿到目标指纹后先调它，再按返回的 path 读条目详情或 loadSkill 加载分类。"

    override val parameters: Map<String, ToolParameter> = mapOf(
        "ports" to ToolParameter(
            name = "ports",
            type = ParameterType.STRING,
            description = "开放端口，逗号分隔，如 443,8443。",
            required = false
        ),
        "banner" to ToolParameter(
            name = "banner",
            type = ParameterType.STRING,
            description = "服务 banner / Server 头 / 版本串原文。",
            required = false
        ),
        "product" to ToolParameter(
            name = "product",
            type = ParameterType.STRING,
            description = "产品名，如 Confluence、FortiOS、runc。",
            required = false
        ),
        "text" to ToolParameter(
            name = "text",
            type = ParameterType.STRING,
            description = "任意指纹描述（标题、报错、页面特征、中文关键词）。",
            required = false
        ),
        "limit" to ToolParameter(
            name = "limit",
            type = ParameterType.INTEGER,
            description = "返回条数，默认 5，最大 20。",
            required = false
        )
    )

    override suspend fun execute(args: Map<String, JsonElement>): ToolResult {
        val ports = args["ports"]?.jsonPrimitive?.contentOrNull.orEmpty()
            .split(',', '，', ' ')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        val banner = args["banner"]?.jsonPrimitive?.contentOrNull.orEmpty()
        val product = args["product"]?.jsonPrimitive?.contentOrNull.orEmpty()
        val text = args["text"]?.jsonPrimitive?.contentOrNull.orEmpty()
        val limit = args["limit"]?.jsonPrimitive?.intOrNull ?: DEFAULT_LIMIT

        if (ports.isEmpty() && banner.isBlank() && product.isBlank() && text.isBlank()) {
            return ToolResult.Error("至少提供一个：ports / banner / product / text", "MISSING_QUERY")
        }

        val hits = runCatching {
            KnowledgeIndex(fileAccess).match(
                KnowledgeIndex.Query(ports = ports, banner = banner, product = product, text = text),
                limit
            )
        }.getOrElse { e ->
            FileLogger.e(TAG, "知识库匹配失败", e)
            return ToolResult.Error("知识库匹配失败：${e.message}", "KB_MATCH_FAILED")
        }

        FileLogger.d(TAG, "kbMatch ports=$ports product=$product -> ${hits.size} 条")
        val payload = buildJsonObject {
            put("count", hits.size)
            put("kb_root", KnowledgeIndex.DEFAULT_ROOT)
            put(
                "hits",
                buildJsonArray {
                    hits.forEach { hit ->
                        add(
                            buildJsonObject {
                                put("score", hit.score)
                                put("category", hit.entry.category)
                                put("file", hit.entry.file)
                                put("path", hit.entry.path)
                                put("title", hit.entry.title)
                                put("cve", hit.entry.cve)
                                put("severity", hit.entry.severity)
                                put("product", hit.entry.product)
                                put("versions", hit.entry.versions)
                                put("entry", hit.entry.entry)
                                put("why", hit.why.joinToString("；"))
                            }
                        )
                    }
                }
            )
            if (hits.isEmpty()) {
                put(
                    "hint",
                    "没命中。知识库在 ${KnowledgeIndex.DEFAULT_ROOT}/kb-*，确认富江破甲包已释放（首次启动自动释放），" +
                        "或换关键词/补版本号再匹配。"
                )
            }
        }
        return ToolResult.Success(payload)
    }
}
