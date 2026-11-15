package com.aicode.feature.agent.domain.tool.fujiang

import com.aicode.core.util.FileLogger
import com.aicode.feature.agent.domain.fujiang.CampaignStore
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
 * 渗透作业链记账：任务、资产、步骤、PoC 尝试、阶段推进都写进
 * `~/.aicode/fujiang/vuln-report/campaigns.json`。
 *
 * 资产 host 必须在任务 scope 内才允许写入；阶段只能沿
 * recon → fingerprint → match → verify → exploit → lateral → report 前进。
 */
class CampaignUpsertTool @Inject constructor(
    private val store: CampaignStore
) : AgentTool() {
    private companion object {
        const val TAG = "CampaignUpsertTool"
    }

    private val json = Json { prettyPrint = true; encodeDefaults = true }

    override val name = "campaignUpsert"
    override val description =
        "管理本地渗透作业链台账（~/.aicode/fujiang/vuln-report/campaigns.json）。" +
            "action=create 建任务（必须给 name 与 scope）；asset 记资产（host 必须在 scope 内）；" +
            "step 记命令与结论；attempt 记某条 PoC 的尝试结果；advance 推进阶段；done 收尾；remove 删任务。" +
            "阶段链：recon → fingerprint → match → verify → exploit → lateral → report。"

    override val permissionPolicy = ToolPermissionPolicy.AUTO_APPROVE
    override val capabilities = setOf(ToolCapability.MODIFY_AGENT_CONFIG)

    override val parameters: Map<String, ToolParameter> = mapOf(
        "action" to ToolParameter(
            name = "action",
            type = ParameterType.STRING,
            description = "create / patch / asset / step / attempt / advance / done / remove",
            required = true,
            enum = listOf("create", "patch", "asset", "step", "attempt", "advance", "done", "remove")
        ),
        "campaignId" to ToolParameter(
            name = "campaignId",
            type = ParameterType.STRING,
            description = "任务 id（create 之外都必填）",
            required = false
        ),
        "name" to ToolParameter(
            name = "name",
            type = ParameterType.STRING,
            description = "任务名（create 必填）",
            required = false
        ),
        "scope" to ToolParameter(
            name = "scope",
            type = ParameterType.STRING,
            description = "授权范围：域名 / IP / CIDR，逗号或空格分隔（create 必填）；exclude 用 ! 前缀，如 !test.a.com",
            required = false
        ),
        "objective" to ToolParameter(
            name = "objective",
            type = ParameterType.STRING,
            description = "任务目标，一句话（用于完成判据）",
            required = false
        ),
        "stage" to ToolParameter(
            name = "stage",
            type = ParameterType.STRING,
            description = "直接设置阶段",
            required = false,
            enum = CampaignStore.STAGES
        ),
        "host" to ToolParameter(
            name = "host",
            type = ParameterType.STRING,
            description = "资产 host（asset 必填）",
            required = false
        ),
        "port" to ToolParameter(
            name = "port",
            type = ParameterType.INTEGER,
            description = "资产端口",
            required = false
        ),
        "fingerprint" to ToolParameter(
            name = "fingerprint",
            type = ParameterType.STRING,
            description = "资产指纹：banner / 响应头 / 版本",
            required = false
        ),
        "status" to ToolParameter(
            name = "status",
            type = ParameterType.STRING,
            description = "资产状态：new / fingerprinted / verified / exploited / blocked",
            required = false,
            enum = listOf("new", "fingerprinted", "verified", "exploited", "blocked")
        ),
        "command" to ToolParameter(
            name = "command",
            type = ParameterType.STRING,
            description = "本步执行的命令（step 用）",
            required = false
        ),
        "result" to ToolParameter(
            name = "result",
            type = ParameterType.STRING,
            description = "本步结论（step 用）",
            required = false
        ),
        "kb" to ToolParameter(
            name = "kb",
            type = ParameterType.STRING,
            description = "本次尝试对应的知识库条目（attempt 用）",
            required = false
        ),
        "outcome" to ToolParameter(
            name = "outcome",
            type = ParameterType.STRING,
            description = "尝试结果：hit / miss / blocked / error（attempt 用）",
            required = false,
            enum = listOf("hit", "miss", "blocked", "error")
        ),
        "note" to ToolParameter(
            name = "note",
            type = ParameterType.STRING,
            description = "备注",
            required = false
        ),
        "rounds" to ToolParameter(
            name = "rounds",
            type = ParameterType.INTEGER,
            description = "已进行轮次（patch 用）",
            required = false
        ),
        "maxRounds" to ToolParameter(
            name = "maxRounds",
            type = ParameterType.INTEGER,
            description = "最大轮次，默认 8，范围 1-30",
            required = false
        ),
        "autopilot" to ToolParameter(
            name = "autopilot",
            type = ParameterType.BOOLEAN,
            description = "是否自动续跑（默认 true；Android 端由 pipelineNext 驱动，本字段只做记录）",
            required = false
        ),
        "done" to ToolParameter(
            name = "done",
            type = ParameterType.BOOLEAN,
            description = "是否标记完成（patch 用）",
            required = false
        )
    )

    override suspend fun execute(args: Map<String, JsonElement>): ToolResult {
        val action = args["action"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
        val id = args["campaignId"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
        val text = { key: String -> args[key]?.jsonPrimitive?.contentOrNull.orEmpty() }
        val int = { key: String -> args[key]?.jsonPrimitive?.intOrNull }
        val bool = { key: String -> args[key]?.jsonPrimitive?.booleanOrNull }

        return runCatching {
            when (action) {
                "create" -> {
                    val name = text("name")
                    val scope = text("scope")
                    if (name.isBlank()) return ToolResult.Error("create 需要 name", "MISSING_NAME")
                    if (scope.isBlank()) return ToolResult.Error("create 需要 scope（域名 / IP / CIDR）", "MISSING_SCOPE")
                    val campaign = store.create(
                        name = name,
                        scope = scope,
                        objective = text("objective"),
                        maxRounds = int("maxRounds") ?: 8
                    )
                    ToolResult.Success(buildJsonObject { put("campaign", json.encodeToJsonElement(campaign)) })
                }

                "patch" -> requireId(id) {
                    val stage = text("stage").takeIf { it.isNotBlank() }
                    val campaign = store.patch(
                        id = id,
                        stage = stage,
                        objective = text("objective").takeIf { it.isNotBlank() },
                        rounds = int("rounds"),
                        maxRounds = int("maxRounds"),
                        autopilot = bool("autopilot"),
                        done = bool("done")
                    )
                    ToolResult.Success(buildJsonObject { put("campaign", json.encodeToJsonElement(campaign)) })
                }

                "asset" -> requireId(id) {
                    val host = text("host")
                    if (host.isBlank()) return ToolResult.Error("asset 需要 host", "MISSING_HOST")
                    val campaign = store.upsertAsset(
                        id = id,
                        host = host,
                        port = int("port"),
                        fingerprint = text("fingerprint").takeIf { it.isNotBlank() },
                        status = text("status").takeIf { it.isNotBlank() }
                    )
                    ToolResult.Success(buildJsonObject { put("campaign", json.encodeToJsonElement(campaign)) })
                }

                "step" -> requireId(id) {
                    val campaign = store.addStep(
                        id = id,
                        stage = text("stage"),
                        command = text("command"),
                        result = text("result")
                    )
                    ToolResult.Success(buildJsonObject { put("campaign", json.encodeToJsonElement(campaign)) })
                }

                "attempt" -> requireId(id) {
                    val campaign = store.addAttempt(
                        id = id,
                        kb = text("kb"),
                        outcome = text("outcome"),
                        note = text("note")
                    )
                    ToolResult.Success(buildJsonObject { put("campaign", json.encodeToJsonElement(campaign)) })
                }

                "advance" -> requireId(id) {
                    val (campaign, moved) = store.advance(id)
                    ToolResult.Success(
                        buildJsonObject {
                            put("campaign", json.encodeToJsonElement(campaign))
                            put("stage", moved)
                        }
                    )
                }

                "done" -> requireId(id) {
                    val campaign = store.markDone(id, text("result"))
                    ToolResult.Success(buildJsonObject { put("campaign", json.encodeToJsonElement(campaign)) })
                }

                "remove" -> requireId(id) {
                    val removed = store.remove(id)
                    ToolResult.Success(buildJsonObject { put("id", id); put("removed", removed) })
                }

                else -> ToolResult.Error("未知 action：$action", "BAD_ACTION")
            }
        }.getOrElse { failure ->
            FileLogger.w(TAG, "作业链操作失败: ${failure.message}", failure)
            ToolResult.Error("作业链操作失败：${failure.message}", "CAMPAIGN_FAILED")
        }
    }

    private inline fun requireId(id: String, block: () -> ToolResult): ToolResult =
        if (id.isBlank()) ToolResult.Error("该操作需要 campaignId", "MISSING_CAMPAIGN_ID") else block()
}
