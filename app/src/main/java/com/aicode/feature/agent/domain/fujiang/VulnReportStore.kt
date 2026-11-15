package com.aicode.feature.agent.domain.fujiang

import com.aicode.core.util.FileLogger
import com.aicode.feature.workspace.domain.FileAccessProvider
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

/** 一条漏洞记录。字段刻意保持「人能读、AI 能写」，与上游插件的漏洞报告保持一致。 */
@Serializable
data class VulnFinding(
    val id: String = "",
    val title: String = "",
    val severity: String = "medium",
    val category: String = "",
    val cve: String = "",
    val cvss: Int? = null,
    val target: String = "",
    val url: String = "",
    val description: String = "",
    val evidence: String = "",
    val remediation: String = "",
    val references: String = "",
    val status: String = "open",
    val verified: Boolean = false,
    val createdAt: Long = 0,
    val updatedAt: Long = 0
)

@Serializable
private data class VulnReportFile(
    val schema: Int = 1,
    val findings: List<VulnFinding> = emptyList()
)

/**
 * 漏洞报告存储：`~/.aicode/fujiang/vuln-report/findings.json`。
 *
 * AI 侧用 [com.aicode.feature.agent.domain.tool.fujiang.FindingUpsertTool] 写入，
 * 设置页「富江破甲 → 漏洞报告」读同一份文件，谁改都立刻可见。
 */
@Singleton
class VulnReportStore @Inject constructor(
    private val fileAccess: FileAccessProvider
) {
    private companion object {
        const val TAG = "VulnReportStore"
        const val PATH = "~/.aicode/fujiang/vuln-report/findings.json"
        const val MAX_FINDINGS = 500
    }

    private val json = Json {
        prettyPrint = true
        encodeDefaults = true
        ignoreUnknownKeys = true
    }
    private val mutex = Mutex()

    fun list(): List<VulnFinding> = read().findings

    suspend fun upsert(
        id: String?,
        title: String,
        severity: String,
        category: String = "",
        cve: String = "",
        cvss: Int? = null,
        target: String = "",
        url: String = "",
        description: String = "",
        evidence: String = "",
        remediation: String = "",
        references: String = "",
        status: String = "open",
        verified: Boolean = false
    ): VulnFinding = mutex.withLock {
        val current = read().findings.toMutableList()
        val now = System.currentTimeMillis()
        val existing = current.firstOrNull { it.id == id }
        val updated = if (existing != null) {
            existing.copy(
                title = title.ifBlank { existing.title },
                severity = severity.ifBlank { existing.severity },
                category = category.ifBlank { existing.category },
                cve = cve.ifBlank { existing.cve },
                cvss = cvss ?: existing.cvss,
                target = target.ifBlank { existing.target },
                url = url.ifBlank { existing.url },
                description = description.ifBlank { existing.description },
                evidence = evidence.ifBlank { existing.evidence },
                remediation = remediation.ifBlank { existing.remediation },
                references = references.ifBlank { existing.references },
                status = status.ifBlank { existing.status },
                verified = verified || existing.verified,
                updatedAt = now
            )
        } else {
            VulnFinding(
                id = UUID.randomUUID().toString(),
                title = title,
                severity = severity,
                category = category,
                cve = cve,
                cvss = cvss,
                target = target,
                url = url,
                description = description,
                evidence = evidence,
                remediation = remediation,
                references = references,
                status = status,
                verified = verified,
                createdAt = now,
                updatedAt = now
            )
        }
        if (existing != null) current[current.indexOf(existing)] = updated else current.add(0, updated)
        write(current.take(MAX_FINDINGS))
        updated
    }

    suspend fun delete(id: String): Boolean = mutex.withLock {
        val current = read().findings.toMutableList()
        val removed = current.removeAll { it.id == id }
        if (removed) write(current)
        removed
    }

    suspend fun clear() = mutex.withLock { write(emptyList()) }

    private fun read(): VulnReportFile {
        if (!fileAccess.isFile(PATH)) return VulnReportFile()
        return runCatching {
            json.decodeFromString<VulnReportFile>(fileAccess.readFile(PATH))
        }.getOrElse {
            FileLogger.w(TAG, "漏洞报告解析失败: ${it.message}", it)
            VulnReportFile()
        }
    }

    private fun write(findings: List<VulnFinding>) {
        runCatching {
            fileAccess.writeFile(PATH, json.encodeToString(VulnReportFile(findings = findings)) + "\n")
        }.onFailure {
            FileLogger.w(TAG, "漏洞报告写入失败: ${it.message}", it)
        }
    }
}
