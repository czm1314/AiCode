package com.aicode.feature.agent.domain.tool.fujiang

import com.aicode.feature.agent.domain.skill.SkillEntry
import com.aicode.feature.agent.domain.skill.SkillRepository
import com.aicode.feature.agent.domain.tool.AgentTool
import com.aicode.feature.agent.domain.tool.ParameterType
import com.aicode.feature.agent.domain.tool.ToolCapability
import com.aicode.feature.agent.domain.tool.ToolParameter
import com.aicode.feature.agent.domain.tool.ToolPermissionPolicy
import com.aicode.feature.agent.domain.tool.ToolResult
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.add
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import javax.inject.Inject

/**
 * 本地技能库检索：给关键词，返回按名字/描述/正文打分的技能，可选带回第一名正文。
 *
 * 覆盖 `~/.aicode/skills` 与项目 `.aicode/skills` 两处；禁用名单里的技能不出现在结果里
 * （与系统提示词里注入的技能清单保持一致）。
 */
class SkillSearchTool @Inject constructor(
    private val skillRepository: SkillRepository
) : AgentTool() {
    private companion object {
        const val DEFAULT_LIMIT = 8
        const val MAX_CONTENT = 12000
    }

    override val name = "skillSearch"
    override val description =
        "按关键词在本地技能库里检索技能，返回 name/description/路径/得分。read=true 时同时返回命中第一名的完整正文" +
            "（截断 $MAX_CONTENT 字符）。找不到合适的技能时再用 kbMatch 按端口/指纹匹配 CVE 条目。"

    override val permissionPolicy = ToolPermissionPolicy.AUTO_APPROVE
    override val capabilities = setOf(ToolCapability.READ_AGENT_CONFIG)

    override val parameters: Map<String, ToolParameter> = mapOf(
        "query" to ToolParameter(
            name = "query",
            type = ParameterType.STRING,
            description = "关键词：技能名、漏洞名、产品名、动作（如「confluence」「反序列化」「提权」）",
            required = true
        ),
        "limit" to ToolParameter(
            name = "limit",
            type = ParameterType.INTEGER,
            description = "返回条数，默认 8，最大 20",
            required = false
        ),
        "read" to ToolParameter(
            name = "read",
            type = ParameterType.BOOLEAN,
            description = "是否返回命中第一名的完整正文，默认 false",
            required = false
        )
    )

    override suspend fun execute(args: Map<String, JsonElement>): ToolResult {
        val query = args["query"]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
        if (query.isBlank()) return ToolResult.Error("query 不能为空", "MISSING_QUERY")
        val limit = (args["limit"]?.jsonPrimitive?.intOrNull ?: DEFAULT_LIMIT).coerceIn(1, 20)
        val withContent = args["read"]?.jsonPrimitive?.booleanOrNull ?: false

        val entries = skillRepository.listAllSkills()
        val scored = entries.mapNotNull { entry -> score(entry, query)?.let { entry to it } }
            .sortedWith(compareByDescending<Pair<SkillEntry, Scored>> { it.second.score }.thenBy { it.first.skill.name })
            .take(limit)

        val payload = buildJsonObject {
            put("count", scored.size)
            put(
                "hits",
                buildJsonArray {
                    scored.forEach { (entry, scored) ->
                        add(
                            buildJsonObject {
                                put("name", entry.skill.name)
                                put("scope", entry.scope.name.lowercase())
                                put("score", scored.score)
                                put("description", entry.skill.description)
                                put("path", entry.skill.dirPath.orEmpty())
                                put("why", scored.why.joinToString("；"))
                            }
                        )
                    }
                }
            )
            if (withContent) {
                val first = scored.firstOrNull()?.first?.skill
                if (first != null) {
                    put("name", first.name)
                    put("content", first.instructions.take(MAX_CONTENT))
                    put("truncated", first.instructions.length > MAX_CONTENT)
                }
            }
            if (scored.isEmpty()) {
                put("hint", "没命中技能。知识库类条目请改用 kbMatch 按端口/指纹匹配。")
            }
        }
        return ToolResult.Success(payload)
    }

    private data class Scored(val score: Int, val why: List<String>)

    private fun score(entry: SkillEntry, query: String): Scored? {
        val needle = query.lowercase()
        val tokens = needle.split(Regex("[\\s,，、/]+")).filter { it.isNotBlank() }
        val skill = entry.skill
        val name = skill.name.lowercase()
        val description = skill.description.lowercase()
        val body = skill.instructions.lowercase()

        var score = 0
        val why = ArrayList<String>(3)
        if (name.contains(needle)) {
            score += 60
            why += "技能名"
        }
        if (description.contains(needle)) {
            score += 25
            why += "描述"
        }
        var keywordHits = 0
        for (token in tokens) {
            if (name.contains(token)) {
                score += 20
                keywordHits++
            } else if (description.contains(token)) {
                score += 10
                keywordHits++
            } else if (body.contains(token)) {
                score += 4
            }
        }
        if (keywordHits > 0) why += "关键词 $keywordHits 个"
        if (score == 0) return null
        return Scored(score, why)
    }
}
