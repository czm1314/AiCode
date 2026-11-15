package com.aicode.feature.agent.domain.tool.fujiang

import com.aicode.core.util.FileLogger
import com.aicode.feature.agent.domain.fujiang.CampaignStore
import com.aicode.feature.agent.domain.skill.KnowledgeIndex
import com.aicode.feature.agent.domain.tool.AgentTool
import com.aicode.feature.agent.domain.tool.ParameterType
import com.aicode.feature.agent.domain.tool.ToolCapability
import com.aicode.feature.agent.domain.tool.ToolParameter
import com.aicode.feature.agent.domain.tool.ToolPermissionPolicy
import com.aicode.feature.agent.domain.tool.ToolResult
import com.aicode.feature.workspace.domain.FileAccessProvider
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import javax.inject.Inject

/**
 * 作业链的「下一步」：阶段、进度、完成判据，外加最多三条待处理资产的漏洞候选。
 *
 * 候选来自本地知识库 `kbMatch` 的打分，纯本地、不联网；只给方向，不代表条目已在目标上验证。
 */
class PipelineNextTool @Inject constructor(
    private val store: CampaignStore,
    private val fileAccess: FileAccessProvider
) : AgentTool() {

    override val name = "pipelineNext"
    override val description =
        "读取渗透作业链的下一步：阶段、进度、完成判据、以及最多三条 nextActions（按待处理资产的指纹做过知识库匹配）。" +
            "不传 campaignId 时返回全部任务的阶段概览。做完一步就再调一次，直到 done=true。"

    override val permissionPolicy = ToolPermissionPolicy.AUTO_APPROVE
    override val capabilities = setOf(ToolCapability.READ_AGENT_CONFIG)

    override val parameters: Map<String, ToolParameter> = mapOf(
        "campaignId" to ToolParameter(
            name = "campaignId",
            type = ParameterType.STRING,
            description = "任务 id；不传则只列任务概览。",
            required = false
        )
    )

    override suspend fun execute(args: Map<String, JsonElement>): ToolResult {
        val id = args["campaignId"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
        val all = store.list()
        if (id.isBlank()) {
            return ToolResult.Success(
                buildJsonObject {
                    put("count", all.size)
                    put(
                        "campaigns",
                        buildJsonArray {
                            all.forEach { campaign ->
                                add(
                                    buildJsonObject {
                                        put("id", campaign.id)
                                        put("name", campaign.name)
                                        put("stage", campaign.stage)
                                        put("rounds", campaign.rounds)
                                        put("maxRounds", campaign.maxRounds)
                                        put("assets", campaign.assets.size)
                                        put("done", campaign.done)
                                    }
                                )
                            }
                        }
                    )
                    put("hint", "传 campaignId 看具体下一步。")
                }
            )
        }

        val campaign = all.firstOrNull { it.id == id }
            ?: return ToolResult.Error("任务不存在：$id", "CAMPAIGN_NOT_FOUND")

        val stageIndex = CampaignStore.STAGES.indexOf(campaign.stage).coerceAtLeast(0)
        val pending = campaign.assets
            .filter { it.status != "exploited" && it.status != "blocked" }
            .take(3)

        val nextActions = runCatching {
            val index = KnowledgeIndex(fileAccess)
            pending.map { asset ->
                val hits = index.match(
                    KnowledgeIndex.Query(
                        ports = if (asset.port > 0) listOf(asset.port.toString()) else emptyList(),
                        banner = asset.fingerprint,
                        text = asset.fingerprint
                    ),
                    3
                )
                buildJsonObject {
                    put("host", asset.host)
                    put("port", asset.port)
                    put("status", asset.status)
                    put("fingerprint", asset.fingerprint)
                    put(
                        "kb",
                        buildJsonArray {
                            hits.forEach { hit ->
                                add(
                                    buildJsonObject {
                                        put("file", hit.entry.file)
                                        put("category", hit.entry.category)
                                        put("title", hit.entry.title)
                                        put("score", hit.score)
                                        put("why", hit.why.joinToString("；"))
                                    }
                                )
                            }
                        }
                    )
                }
            }
        }.getOrElse { e ->
            FileLogger.w("PipelineNextTool", "知识库匹配失败: ${e.message}", e)
            emptyList()
        }

        return ToolResult.Success(
            buildJsonObject {
                put("campaign", kotlinx.serialization.json.Json.encodeToJsonElement(campaign))
                put("done", campaign.done)
                put(
                    "progress",
                    buildJsonObject {
                        put("stage", campaign.stage)
                        put("stageIndex", stageIndex)
                        put("stageTotal", CampaignStore.STAGES.size)
                        put("rounds", campaign.rounds)
                        put("maxRounds", campaign.maxRounds)
                        put("assets", campaign.assets.size)
                        put("pendingAssets", campaign.assets.size - pending.size.coerceAtMost(campaign.assets.size))
                    }
                )
                put(
                    "criteria",
                    "目标达成后用 campaignUpsert action=done 收尾；每步用 action=step 记账，" +
                        "PoC 结果用 action=attempt 记 hit/miss/blocked/error。"
                )
                put("nextActions", buildJsonArray { nextActions.forEach { add(it) } })
                if (nextActions.isEmpty()) {
                    put("hint", "没有待处理资产。先用 campaignUpsert action=asset 写入资产与指纹。")
                }
            }
        )
    }
}
