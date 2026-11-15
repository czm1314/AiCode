package com.aicode.feature.agent.domain.tool.fujiang

import com.aicode.core.util.FileLogger
import com.aicode.feature.agent.domain.fujiang.VulnReportStore
import com.aicode.feature.agent.domain.tool.AgentTool
import com.aicode.feature.agent.domain.tool.ParameterType
import com.aicode.feature.agent.domain.tool.ToolCapability
import com.aicode.feature.agent.domain.tool.ToolParameter
import com.aicode.feature.agent.domain.tool.ToolPermissionPolicy
import com.aicode.feature.agent.domain.tool.ToolResult
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import javax.inject.Inject

/**
 * 漏洞报告写入：一条记录一个条目，写进 `~/.aicode/fujiang/vuln-report/findings.json`。
 *
 * 新增要求 target 与 evidence 同时给出——没有目标和证据的「漏洞」不值得进报告；
 * 带 id 时按 id 更新，只覆盖传了的字段，其余保留。
 */
class FindingUpsertTool @Inject constructor(
    private val store: VulnReportStore
) : AgentTool() {
    private companion object {
        const val TAG = "FindingUpsertTool"
    }

    private val json = Json { prettyPrint = true; encodeDefaults = true }

    override val name = "findingUpsert"
    override val description =
        "写入/更新一条漏洞记录到本地漏洞报告（~/.aicode/fujiang/vuln-report/findings.json）。" +
            "新增时 target 与 evidence 必填（否则拒绝写入）；有 id 就是更新那条。action=delete 按 id 删除，" +
            "action=clear 清空整份报告。写完后用户在「设置 → 富江破甲 → 漏洞报告」里能看到同一份数据。"

    override val permissionPolicy = ToolPermissionPolicy.AUTO_APPROVE
    override val capabilities = setOf(ToolCapability.MODIFY_AGENT_CONFIG)

    override val parameters: Map<String, ToolParameter> = mapOf(
        "action" to ToolParameter(
            name = "action",
            type = ParameterType.STRING,
            description = "upsert（默认）/ delete / clear",
            required = false,
            enum = listOf("upsert", "delete", "clear")
        ),
        "id" to ToolParameter(
            name = "id",
            type = ParameterType.STRING,
            description = "已有条目的 id（更新或删除时给）",
            required = false
        ),
        "title" to ToolParameter(
            name = "title",
            type = ParameterType.STRING,
            description = "漏洞标题",
            required = false
        ),
        "severity" to ToolParameter(
            name = "severity",
            type = ParameterType.STRING,
            description = "critical / high / medium / low / info",
            required = false,
            enum = listOf("critical", "high", "medium", "low", "info")
        ),
        "category" to ToolParameter(
            name = "category",
            type = ParameterType.STRING,
            description = "漏洞类别（越权 / SQLi / RCE …）",
            required = false
        ),
        "cve" to ToolParameter(
            name = "cve",
            type = ParameterType.STRING,
            description = "CVE 编号，无则留空",
            required = false
        ),
        "cvss" to ToolParameter(
            name = "cvss",
            type = ParameterType.INTEGER,
            description = "CVSS 分数 0-10",
            required = false
        ),
        "target" to ToolParameter(
            name = "target",
            type = ParameterType.STRING,
            description = "目标（域名 / IP / 系统名）",
            required = false
        ),
        "url" to ToolParameter(
            name = "url",
            type = ParameterType.STRING,
            description = "具体位置（URL / 接口 / 文件路径）",
            required = false
        ),
        "description" to ToolParameter(
            name = "description",
            type = ParameterType.STRING,
            description = "漏洞说明与复现步骤",
            required = false
        ),
        "evidence" to ToolParameter(
            name = "evidence",
            type = ParameterType.STRING,
            description = "证据：请求与响应原文、命令输出（新增必填）",
            required = false
        ),
        "remediation" to ToolParameter(
            name = "remediation",
            type = ParameterType.STRING,
            description = "修复建议",
            required = false
        ),
        "references" to ToolParameter(
            name = "references",
            type = ParameterType.STRING,
            description = "参考链接",
            required = false
        ),
        "status" to ToolParameter(
            name = "status",
            type = ParameterType.STRING,
            description = "open / fixed / accepted / false-positive",
            required = false,
            enum = listOf("open", "fixed", "accepted", "false-positive")
        ),
        "verified" to ToolParameter(
            name = "verified",
            type = ParameterType.BOOLEAN,
            description = "是否已实测验证（需同时有 target 与 evidence）",
            required = false
        )
    )

    override suspend fun execute(args: Map<String, JsonElement>): ToolResult {
        val action = args["action"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty().ifBlank { "upsert" }
        return when (action) {
            "clear" -> runCatching { store.clear() }
                .fold(
                    onSuccess = { ToolResult.Success(buildJsonObject { put("cleared", true) }) },
                    onFailure = { error("清空失败", it) }
                )

            "delete" -> {
                val id = args["id"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
                if (id.isBlank()) return ToolResult.Error("delete 需要 id", "MISSING_ID")
                runCatching { store.delete(id) }.fold(
                    onSuccess = { ToolResult.Success(buildJsonObject { put("id", id); put("deleted", it) }) },
                    onFailure = { error("删除失败", it) }
                )
            }

            "upsert" -> {
                val id = args["id"]?.jsonPrimitive?.contentOrNull?.trim()?.takeIf { it.isNotEmpty() }
                val target = args["target"]?.jsonPrimitive?.contentOrNull.orEmpty()
                val evidence = args["evidence"]?.jsonPrimitive?.contentOrNull.orEmpty()
                if (id == null && (target.isBlank() || evidence.isBlank())) {
                    return ToolResult.Error(
                        "新增条目必须同时提供 target 与 evidence：没有目标和证据的记录不进报告",
                        "MISSING_EVIDENCE"
                    )
                }
                runCatching {
                    store.upsert(
                        id = id,
                        title = args["title"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                        severity = args["severity"]?.jsonPrimitive?.contentOrNull.orEmpty().ifBlank { "medium" },
                        category = args["category"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                        cve = args["cve"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                        cvss = args["cvss"]?.jsonPrimitive?.intOrNull,
                        target = target,
                        url = args["url"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                        description = args["description"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                        evidence = evidence,
                        remediation = args["remediation"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                        references = args["references"]?.jsonPrimitive?.contentOrNull.orEmpty(),
                        status = args["status"]?.jsonPrimitive?.contentOrNull.orEmpty().ifBlank { "open" },
                        verified = args["verified"]?.jsonPrimitive?.booleanOrNull ?: false
                    )
                }.fold(
                    onSuccess = { finding ->
                        FileLogger.d(TAG, "finding 已写入: ${finding.id} ${finding.title}")
                        ToolResult.Success(buildJsonObject { put("item", json.encodeToJsonElement(finding)) })
                    },
                    onFailure = { error("写入失败", it) }
                )
            }

            else -> ToolResult.Error("未知 action：$action", "BAD_ACTION")
        }
    }

    private fun error(prefix: String, failure: Throwable): ToolResult.Error {
        FileLogger.w(TAG, "$prefix: ${failure.message}", failure)
        return ToolResult.Error("$prefix：${failure.message}", "FINDING_FAILED")
    }
}
