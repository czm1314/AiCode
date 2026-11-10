package com.aicode.feature.agent.domain.skill

import com.aicode.core.util.FileLogger
import com.aicode.feature.workspace.domain.FileAccessProvider

/**
 * CVE / PoC 知识库的本地索引与指纹匹配（「富江破甲包」的 kbMatch 能力）。
 *
 * 语料是随 App 附带的 `~/.aicode/skills/kb-*/` 目录，一条 `.md` 一个漏洞条目，
 * 元数据全在 frontmatter（title / cve / severity / product / versions / ports / keywords / entry）。
 *
 * 打分规则（与上游插件 automation.js 一致，只做本地排序，不联网、不执行任何东西）：
 * 端口命中 +35、产品命中 +60、CVE 命中 +20、英文关键词每条 +8（上限 16）、
 * 中文关键词每条 8+2×(字数-2)（上限 40）、标题词命中每条 +6（上限 18，产品已命中时不加分）、
 * 严重度为 critical 时 +5。
 */
class KnowledgeIndex(
    private val fileAccess: FileAccessProvider,
    private val root: String = DEFAULT_ROOT
) {

    data class Entry(
        val file: String,
        val category: String,
        val path: String,
        val title: String,
        val cve: String,
        val severity: String,
        val product: String,
        val versions: String,
        val entry: String,
        val ports: List<String>,
        val keywordTokens: List<String>,
        val rawKeywords: List<String>,
        val textTokens: List<String>
    )

    data class Hit(val entry: Entry, val score: Int, val why: List<String>)

    /** 匹配输入：都可缺省，全空返回空列表。 */
    data class Query(
        val ports: List<String> = emptyList(),
        val banner: String = "",
        val product: String = "",
        val text: String = "",
        val headers: String = ""
    )

    /** 逐条读语料建索引；目录不存在或读失败都降级为空，不抛异常。 */
    fun entries(): List<Entry> = runCatching {
        val files = fileAccess.listFilesRecursive(root, MAX_DEPTH)
            .filter {
                it.endsWith(".md", ignoreCase = true) &&
                    !it.substringAfterLast('/').equals(SKILL_FILE, ignoreCase = true)
            }
        files.mapNotNull { relative ->
            val path = "${root.trimEnd('/')}/$relative"
            val text = runCatching { fileAccess.readFile(path) }.getOrElse {
                FileLogger.w(TAG, "读取知识库条目失败: $path", it)
                return@mapNotNull null
            }
            val fields = parseFrontmatter(text)
            val file = relative.substringAfterLast('/')
            val category = relative.substringBefore('/', "")
            Entry(
                file = file,
                category = category,
                path = path,
                title = fields["title"]?.takeIf { it.isNotBlank() } ?: file,
                cve = fields["cve"].orEmpty(),
                severity = fields["severity"]?.takeIf { it.isNotBlank() } ?: "medium",
                product = fields["product"].orEmpty(),
                versions = fields["versions"].orEmpty(),
                entry = fields["entry"].orEmpty(),
                ports = fields["ports"].orEmpty()
                    .split(Regex("[,，\\s]+"))
                    .filter { it.isNotEmpty() && it.all { c -> c.isDigit() } },
                keywordTokens = tokens(fields["keywords"].orEmpty()),
                rawKeywords = fields["keywords"].orEmpty()
                    .split(Regex("[,，、\\s]+"))
                    .map { it.trim() }
                    .filter { it.length >= 2 },
                textTokens = tokens(
                    listOf(
                        fields["title"].orEmpty(), fields["product"].orEmpty(), fields["cve"].orEmpty(),
                        fields["keywords"].orEmpty(), fields["entry"].orEmpty(), fields["versions"].orEmpty()
                    ).joinToString(" ")
                )
            )
        }.sortedBy { it.file }
    }.getOrElse { e ->
        FileLogger.w(TAG, "建立知识库索引失败: $root", e)
        emptyList()
    }

    fun match(query: Query, limit: Int = 5): List<Hit> {
        val wantedPorts = query.ports.map { it.trim() }.filter { it.isNotEmpty() }
        val haystackText = listOf(query.banner, query.product, query.text, query.headers)
            .filter { it.isNotBlank() }
            .joinToString(" ")
            .lowercase()
        if (haystackText.isBlank() && wantedPorts.isEmpty()) return emptyList()
        val haystackTokens = tokens(haystackText).toSet()

        val scored = ArrayList<Hit>()
        for (item in entries()) {
            var score = 0
            val why = ArrayList<String>(3)
            val portHits = item.ports.filter { wantedPorts.contains(it) }
            if (portHits.isNotEmpty()) {
                score += 35
                why += "端口 " + portHits.joinToString(",")
            }
            val productHit = tokens(item.product)
                .any { it.length >= 3 && it !in STOPWORDS && hasWord(haystackText, it) }
            if (productHit) {
                score += 60
                why += "产品 ${item.product}"
            }
            if (item.cve.isNotBlank() && item.cve != "无" && hasWord(haystackText, item.cve)) {
                score += 20
                why += "CVE ${item.cve}"
            }
            val kwHits = item.keywordTokens.filter {
                it.length >= 3 && it !in STOPWORDS && hasWord(haystackText, it)
            }
            if (kwHits.isNotEmpty()) {
                score += minOf(16, kwHits.size * 8)
                why += "关键词 " + kwHits.take(4).joinToString("/")
            }
            val cnHits = item.rawKeywords.filter {
                CJK.containsMatchIn(it) && haystackText.contains(it.lowercase())
            }
            if (cnHits.isNotEmpty()) {
                val cnScore = cnHits.sumOf { 8 + maxOf(0, (it.length - 2) * 2) }
                score += minOf(40, cnScore)
                why += "中文关键词 " + cnHits.take(3).joinToString("/")
            }
            val titleHits = item.textTokens.filter {
                it.length >= 4 && it !in STOPWORDS && haystackTokens.contains(it)
            }
            if (!productHit && titleHits.isNotEmpty()) {
                score += minOf(18, titleHits.size * 6)
                why += "命中 " + titleHits.take(3).joinToString("/")
            }
            if (score == 0) continue
            if (item.severity == "critical") score += 5
            scored += Hit(item, score, why)
        }
        return scored.sortedWith(compareByDescending<Hit> { it.score }.thenBy { it.entry.file })
            .take(limit.coerceIn(1, 20))
    }

    companion object Statics {
        private const val TAG = "KnowledgeIndex"
        const val DEFAULT_ROOT = "~/.aicode/skills"
        private const val SKILL_FILE = "skill.md"
        private const val MAX_DEPTH = 3

        /** 太泛的词不参与打分，否则 "web"/"server" 会把所有条目拉平。 */
        private val STOPWORDS = setOf(
            "gateway", "server", "service", "client", "web", "http", "https", "httpd", "api",
            "admin", "login", "default", "remote", "manager", "console", "portal", "access",
            "open", "source", "code", "test", "main", "index", "config", "system", "vpn",
            "ssl", "tls", "ipsec", "cloud", "security", "edge", "app", "gate", "proxy", "auth"
        )

        private val CJK = Regex("[\\u4e00-\\u9fa5]")
        private val TOKEN_SPLIT = Regex("[^a-z0-9.+_/-]+")

        /** frontmatter 只认 `---` 包起来的平坦 `key: value`，值不做 YAML 语义展开。 */
        fun parseFrontmatter(markdown: String): Map<String, String> {
            val text = markdown.removePrefix("\uFEFF")
            if (!text.startsWith("---")) return emptyMap()
            val end = text.indexOf("\n---", startIndex = 3)
            if (end < 0) return emptyMap()
            val map = LinkedHashMap<String, String>()
            for (line in text.substring(3, end).split('\n')) {
                val index = line.indexOf(':')
                if (index <= 0) continue
                val key = line.substring(0, index).trim()
                if (!KEY_PATTERN.matches(key)) continue
                map[key] = line.substring(index + 1).trim().trim('"').trim('\'')
            }
            return map
        }

        fun tokens(value: String): List<String> = value.lowercase()
            .split(TOKEN_SPLIT)
            .filter { it.length >= 2 }

        /** 整词匹配：`active` 不能命中 `activemq`。 */
        fun hasWord(haystack: String, word: String): Boolean =
            Regex("(?:^|[^a-z0-9])${Regex.escape(word.lowercase())}(?:$|[^a-z0-9])")
                .containsMatchIn(haystack)

        private val KEY_PATTERN = Regex("^[a-z][a-z0-9-]*$")
    }
}
