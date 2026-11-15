package com.aicode.feature.agent.domain.fujiang

import com.aicode.core.util.FileLogger
import com.aicode.feature.workspace.domain.FileAccessProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.InetAddress
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
data class CampaignScope(
    val domains: List<String> = emptyList(),
    val cidrs: List<String> = emptyList(),
    val exclude: List<String> = emptyList()
)

@Serializable
data class CampaignAsset(
    val host: String,
    val port: Int = 0,
    val fingerprint: String = "",
    val status: String = "new"
)

@Serializable
data class CampaignStep(
    val stage: String = "",
    val command: String = "",
    val result: String = "",
    val at: Long = 0
)

@Serializable
data class CampaignAttempt(
    val kb: String = "",
    val outcome: String = "",
    val note: String = "",
    val at: Long = 0
)

@Serializable
data class Campaign(
    val id: String = "",
    val name: String = "",
    val objective: String = "",
    val scope: CampaignScope = CampaignScope(),
    val stage: String = "recon",
    val rounds: Int = 0,
    val maxRounds: Int = 8,
    val autopilot: Boolean = true,
    val done: Boolean = false,
    val assets: List<CampaignAsset> = emptyList(),
    val steps: List<CampaignStep> = emptyList(),
    val attempts: List<CampaignAttempt> = emptyList(),
    val createdAt: Long = 0,
    val updatedAt: Long = 0
)

@Serializable
private data class CampaignFile(
    val schema: Int = 1,
    val campaigns: List<Campaign> = emptyList()
)

/**
 * 渗透作业链台账：`~/.aicode/fujiang/vuln-report/campaigns.json`。
 *
 * 阶段链 recon → fingerprint → match → verify → exploit → lateral → report 单向推进；
 * 资产必须落在任务授权范围内才允许记账，避免 AI 把范围外的 host 写进台账。
 */
@Singleton
class CampaignStore @Inject constructor(
    private val fileAccess: FileAccessProvider
) {
    companion object {
        const val TAG = "CampaignStore"
        const val PATH = "~/.aicode/fujiang/vuln-report/campaigns.json"
        val STAGES = listOf("recon", "fingerprint", "match", "verify", "exploit", "lateral", "report")
        private const val MAX_CAMPAIGNS = 100
        private val LABEL = Regex("^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
    }

    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
        ignoreUnknownKeys = true
    }
    private val mutex = Mutex()

    fun list(): List<Campaign> = read().campaigns

    fun get(id: String): Campaign? = list().firstOrNull { it.id == id }

    suspend fun create(name: String, scope: String, objective: String = "", maxRounds: Int = 8): Campaign =
        mutex.withLock {
            val current = read().campaigns.toMutableList()
            if (current.size >= MAX_CAMPAIGNS) {
                current.removeLastOrNull()
            }
            val now = System.currentTimeMillis()
            val campaign = Campaign(
                id = "c-" + UUID.randomUUID().toString().take(8),
                name = name,
                objective = objective,
                scope = parseScope(scope),
                rounds = 0,
                maxRounds = maxRounds.coerceIn(1, 30),
                createdAt = now,
                updatedAt = now
            )
            current.add(0, campaign)
            write(current)
            campaign
        }

    suspend fun patch(
        id: String,
        stage: String? = null,
        objective: String? = null,
        rounds: Int? = null,
        maxRounds: Int? = null,
        autopilot: Boolean? = null,
        done: Boolean? = null
    ): Campaign = mutex.withLock {
        update(id) { campaign ->
            campaign.copy(
                stage = stage ?: campaign.stage,
                objective = objective ?: campaign.objective,
                rounds = rounds ?: campaign.rounds,
                maxRounds = maxRounds?.coerceIn(1, 30) ?: campaign.maxRounds,
                autopilot = autopilot ?: campaign.autopilot,
                done = done ?: campaign.done,
                updatedAt = System.currentTimeMillis()
            )
        }
    }

    suspend fun upsertAsset(
        id: String,
        host: String,
        port: Int? = null,
        fingerprint: String? = null,
        status: String? = null
    ): Campaign = mutex.withLock {
        val normalized = normalizeHost(host)
        update(id) { campaign ->
            val allowed = campaign.scope.domains + campaign.scope.cidrs
            if (allowed.none { scopeMatches(normalized, it) } ||
                campaign.scope.exclude.any { scopeMatches(normalized, it) }
            ) {
                throw IllegalArgumentException("资产不在任务授权范围内：$normalized")
            }
            val assets = campaign.assets.toMutableList()
            val index = assets.indexOfFirst { it.host == normalized && it.port == (port ?: 0) }
            val asset = CampaignAsset(
                host = normalized,
                port = port ?: 0,
                fingerprint = fingerprint ?: assets.getOrNull(index)?.fingerprint.orEmpty(),
                status = status ?: assets.getOrNull(index)?.status ?: "new"
            )
            if (index >= 0) assets[index] = asset else assets.add(asset)
            campaign.copy(assets = assets, updatedAt = System.currentTimeMillis())
        }
    }

    suspend fun addStep(id: String, stage: String, command: String, result: String): Campaign = mutex.withLock {
        update(id) { campaign ->
            campaign.copy(
                steps = campaign.steps + CampaignStep(
                    stage = stage.ifBlank { campaign.stage },
                    command = command,
                    result = result,
                    at = System.currentTimeMillis()
                ),
                updatedAt = System.currentTimeMillis()
            )
        }
    }

    suspend fun addAttempt(id: String, kb: String, outcome: String, note: String): Campaign = mutex.withLock {
        update(id) { campaign ->
            campaign.copy(
                attempts = campaign.attempts + CampaignAttempt(
                    kb = kb,
                    outcome = outcome,
                    note = note,
                    at = System.currentTimeMillis()
                ),
                updatedAt = System.currentTimeMillis()
            )
        }
    }

    /** 推进一格阶段；已到 report 则保持不动。 */
    suspend fun advance(id: String): Pair<Campaign, String> = mutex.withLock {
        var moved = ""
        val campaign = update(id) { campaign ->
            val index = STAGES.indexOf(campaign.stage).coerceAtLeast(0)
            val next = STAGES.getOrNull(index + 1) ?: STAGES.last()
            moved = next
            campaign.copy(
                stage = next,
                rounds = campaign.rounds + 1,
                updatedAt = System.currentTimeMillis()
            )
        }
        campaign to moved
    }

    /** 收尾：阶段置 report、done=true，并把结论文本写进最后一步。 */
    suspend fun markDone(id: String, result: String): Campaign = mutex.withLock {
        update(id) { campaign ->
            val now = System.currentTimeMillis()
            val steps = if (result.isBlank()) campaign.steps else {
                campaign.steps + CampaignStep(stage = "report", result = result, at = now)
            }
            campaign.copy(done = true, stage = "report", steps = steps, updatedAt = now)
        }
    }

    suspend fun remove(id: String): Boolean = mutex.withLock {
        val current = read().campaigns.toMutableList()
        val removed = current.removeAll { it.id == id }
        if (removed) write(current)
        removed
    }

    private inline fun update(id: String, transform: (Campaign) -> Campaign): Campaign {
        val current = read().campaigns.toMutableList()
        val index = current.indexOfFirst { it.id == id }
        require(index >= 0) { "任务不存在：$id" }
        val updated = transform(current[index])
        current[index] = updated
        write(current)
        return updated
    }

    private fun read(): CampaignFile {
        if (!fileAccess.isFile(PATH)) return CampaignFile()
        return runCatching {
            json.decodeFromString<CampaignFile>(fileAccess.readFile(PATH))
        }.getOrElse {
            FileLogger.w(TAG, "作业链解析失败: ${it.message}", it)
            CampaignFile()
        }
    }

    private fun write(campaigns: List<Campaign>) {
        runCatching {
            fileAccess.writeFile(PATH, json.encodeToString(CampaignFile(campaigns = campaigns)) + "\n")
        }.onFailure {
            FileLogger.w(TAG, "作业链写入失败: ${it.message}", it)
        }
    }

    /** 授权范围文本 → 结构：逗号/空格/换行分隔，`!` 前缀为排除项。 */
    fun parseScope(raw: String): CampaignScope {
        val domains = ArrayList<String>()
        val cidrs = ArrayList<String>()
        val exclude = ArrayList<String>()
        for (token in raw.split(',', '，', ' ', '\n', ';')) {
            val item = token.trim()
            if (item.isEmpty()) continue
            if (item.startsWith("!")) {
                exclude += normalizeScopeEntry(item.drop(1))
                continue
            }
            val entry = normalizeScopeEntry(item)
            if (entry.contains('/')) cidrs += entry else domains += entry
        }
        require(domains.isNotEmpty() || cidrs.isNotEmpty()) {
            "授权范围至少需要一个域名、IP 或 CIDR，如 example.com,10.0.0.0/24,!admin.example.com"
        }
        return CampaignScope(
            domains = domains.distinct(),
            cidrs = cidrs.distinct(),
            exclude = exclude.distinct()
        )
    }

    private fun normalizeScopeEntry(value: String): String {
        require(value.isNotBlank()) { "授权范围包含空条目。" }
        if (value.contains('/')) {
            val parts = value.split('/')
            require(parts.size == 2) { "无效 CIDR：$value" }
            val address = parseIp(parts[0]) ?: throw IllegalArgumentException("无效 CIDR：$value")
            val prefix = parts[1].toIntOrNull() ?: throw IllegalArgumentException("无效 CIDR：$value")
            val max = if (address.size == 4) 32 else 128
            require(prefix in 0..max) { "CIDR 前缀超出范围：$value" }
            return "${parts[0]}/$prefix"
        }
        if (value.startsWith("*.")) return "*." + normalizeHost(value.drop(2))
        return normalizeHost(value)
    }

    /** host 归一化：IP 原样小写，域名小写并校验标签；不合法直接拒绝。 */
    fun normalizeHost(raw: String): String {
        val value = raw.trim().trimEnd('.')
        require(value.isNotEmpty() && value.length <= 253) { "资产 host 无效：$raw" }
        if (parseIp(value) != null) return value.lowercase()
        val labels = value.lowercase().split('.')
        require(labels.all { it.isNotEmpty() && it.length <= 63 && LABEL.matches(it) }) {
            "资产 host 必须是域名或 IP 地址：$raw"
        }
        return value.lowercase()
    }

    fun scopeMatches(host: String, entry: String): Boolean {
        if (entry.contains('/')) {
            val parts = entry.split('/')
            val address = parseIp(parts[0]) ?: return false
            val target = parseIp(host) ?: return false
            if (address.size != target.size) return false
            val prefix = parts.getOrNull(1)?.toIntOrNull() ?: return false
            val fullBytes = prefix / 8
            val restBits = prefix % 8
            for (i in 0 until fullBytes) {
                if (address[i] != target[i]) return false
            }
            if (restBits == 0) return true
            val mask = (0xff shl (8 - restBits)) and 0xff
            return (address[fullBytes].toInt() and mask) == (target[fullBytes].toInt() and mask)
        }
        if (parseIp(entry) != null) return parseIp(host) != null && entry.equals(host, ignoreCase = true)
        if (parseIp(host) != null) return false
        val domain = entry.removePrefix("*.").lowercase()
        return host.endsWith("." + domain) || (!entry.startsWith("*.") && host == domain)
    }

    private fun parseIp(value: String): ByteArray? {
        val v4 = value.split('.')
        if (v4.size == 4) {
            val bytes = ByteArray(4)
            for ((index, part) in v4.withIndex()) {
                val number = part.toIntOrNull() ?: return null
                if (number !in 0..255 || part != number.toString()) return null
                bytes[index] = number.toByte()
            }
            return bytes
        }
        if (!value.contains(':')) return null
        return runCatching { InetAddress.getByName(value).address }.getOrNull()
    }
}
