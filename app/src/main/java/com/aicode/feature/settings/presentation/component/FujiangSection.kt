package com.aicode.feature.settings.presentation.component

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.aicode.R
import com.aicode.core.theme.Radius
import com.aicode.core.theme.Spacing
import com.aicode.core.theme.semanticColors
import com.aicode.feature.agent.domain.fujiang.Campaign
import com.aicode.feature.agent.domain.fujiang.VulnFinding
import com.aicode.feature.agent.domain.skill.KnowledgeIndex
import com.aicode.feature.agent.presentation.component.MarkdownContent
import com.aicode.feature.settings.presentation.FujiangViewModel
import compose.icons.FeatherIcons
import compose.icons.feathericons.Book
import compose.icons.feathericons.RefreshCw
import compose.icons.feathericons.Server
import compose.icons.feathericons.Shield

private enum class FujiangTab(@param:StringRes val labelRes: Int) {
    Findings(R.string.fujiang_tab_findings),
    Knowledge(R.string.fujiang_tab_knowledge),
    Campaigns(R.string.fujiang_tab_campaigns)
}

/**
 * 「设置 → 富江破甲」：漏洞报告、知识库、渗透作业链三块。
 *
 * 三份数据都由 AI 工具写入磁盘，页面只读 + 删除，所以每次进入和下拉刷新都重新扫盘。
 */
@Composable
internal fun FujiangSection(viewModel: FujiangViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    var tab by remember { mutableStateOf(FujiangTab.Findings) }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = Spacing.lg, vertical = Spacing.sm),
            horizontalArrangement = Arrangement.spacedBy(Spacing.sm),
            verticalAlignment = Alignment.CenterVertically
        ) {
            FujiangTab.entries.forEach { item ->
                FilterChip(
                    selected = tab == item,
                    onClick = { tab = item },
                    label = { Text(stringResource(item.labelRes)) }
                )
            }
            Spacer(modifier = Modifier.weight(1f))
            IconButton(onClick = viewModel::refresh, enabled = !state.loading) {
                Icon(imageVector = FeatherIcons.RefreshCw, contentDescription = null)
            }
        }

        when (tab) {
            FujiangTab.Findings -> FindingsPane(
                findings = state.findings,
                onDelete = viewModel::deleteFinding
            )

            FujiangTab.Knowledge -> KnowledgePane(
                entries = state.entries,
                viewModel = viewModel
            )

            FujiangTab.Campaigns -> CampaignsPane(
                campaigns = state.campaigns,
                onDelete = viewModel::deleteCampaign
            )
        }
    }
}

@Composable
private fun FindingsPane(findings: List<VulnFinding>, onDelete: (String) -> Unit) {
    var detail by remember { mutableStateOf<VulnFinding?>(null) }
    var pendingDelete by remember { mutableStateOf<VulnFinding?>(null) }

    if (findings.isEmpty()) {
        SettingsEmptyState(
            icon = FeatherIcons.Shield,
            title = stringResource(R.string.fujiang_empty_findings_title),
            hint = stringResource(R.string.fujiang_empty_findings_hint),
            modifier = Modifier.fillMaxSize()
        )
        return
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = Spacing.lg, vertical = Spacing.sm),
        verticalArrangement = Arrangement.spacedBy(Spacing.md)
    ) {
        itemsIndexed(findings, key = { _, item -> item.id }) { index, finding ->
            LazyGroupItem(index = index, lastIndex = findings.lastIndex) {
                SettingsRow(
                    icon = FeatherIcons.Shield,
                    title = finding.title.ifBlank { finding.target.ifBlank { finding.id } },
                    subtitle = listOf(finding.severity.uppercase(), finding.target, finding.category)
                        .filter { it.isNotBlank() }
                        .joinToString(" · "),
                    onClick = { detail = finding }
                )
            }
        }
    }

    detail?.let { finding ->
        FindingDetailDialog(
            finding = finding,
            onDismiss = { detail = null },
            onDelete = {
                detail = null
                pendingDelete = finding
            }
        )
    }

    pendingDelete?.let { finding ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.fujiang_delete_finding_title)) },
            text = { Text(stringResource(R.string.fujiang_delete_finding_message)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDelete(finding.id)
                        pendingDelete = null
                    }
                ) { Text(stringResource(R.string.common_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.common_cancel))
                }
            }
        )
    }
}

@Composable
private fun KnowledgePane(entries: List<KnowledgeIndex.Entry>, viewModel: FujiangViewModel) {
    var viewing by remember { mutableStateOf<KnowledgeIndex.Entry?>(null) }

    if (entries.isEmpty()) {
        SettingsEmptyState(
            icon = FeatherIcons.Book,
            title = stringResource(R.string.fujiang_empty_knowledge_title),
            hint = stringResource(R.string.fujiang_empty_knowledge_hint),
            modifier = Modifier.fillMaxSize()
        )
        return
    }

    val grouped = remember(entries) { entries.groupBy { it.category.ifBlank { "-" } } }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = Spacing.lg, vertical = Spacing.sm)
    ) {
        grouped.forEach { (category, items) ->
            item(key = "header-$category") {
                SettingsGroupHeader(
                    text = "$category · " + stringResource(R.string.fujiang_entry_count, items.size)
                )
            }
            itemsIndexed(items, key = { _, entry -> entry.path }) { index, entry ->
                LazyGroupItem(index = index, lastIndex = items.lastIndex) {
                    SettingsRow(
                        icon = FeatherIcons.Book,
                        title = entry.title,
                        subtitle = listOf(entry.cve, entry.severity)
                            .filter { it.isNotBlank() && it != "无" }
                            .joinToString(" · "),
                        onClick = { viewing = entry }
                    )
                }
            }
            item(key = "spacer-$category") { Spacer(modifier = Modifier.height(Spacing.sm)) }
        }
    }

    viewing?.let { entry ->
        EntryDetailDialog(entry = entry, viewModel = viewModel, onDismiss = { viewing = null })
    }
}

@Composable
private fun CampaignsPane(campaigns: List<Campaign>, onDelete: (String) -> Unit) {
    var detail by remember { mutableStateOf<Campaign?>(null) }
    var pendingDelete by remember { mutableStateOf<Campaign?>(null) }

    if (campaigns.isEmpty()) {
        SettingsEmptyState(
            icon = FeatherIcons.Server,
            title = stringResource(R.string.fujiang_empty_campaigns_title),
            hint = stringResource(R.string.fujiang_empty_campaigns_hint),
            modifier = Modifier.fillMaxSize()
        )
        return
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(horizontal = Spacing.lg, vertical = Spacing.sm),
        verticalArrangement = Arrangement.spacedBy(Spacing.md)
    ) {
        itemsIndexed(campaigns, key = { _, item -> item.id }) { index, campaign ->
            LazyGroupItem(index = index, lastIndex = campaigns.lastIndex) {
                SettingsRow(
                    icon = FeatherIcons.Server,
                    title = campaign.name,
                    subtitle = stringResource(
                        R.string.fujiang_stage_progress,
                        campaign.stage,
                        campaign.rounds,
                        campaign.maxRounds
                    ) + " · " + stringResource(R.string.fujiang_asset_count, campaign.assets.size),
                    onClick = { detail = campaign }
                )
            }
        }
    }

    detail?.let { campaign ->
        CampaignDetailDialog(
            campaign = campaign,
            onDismiss = { detail = null },
            onDelete = {
                detail = null
                pendingDelete = campaign
            }
        )
    }

    pendingDelete?.let { campaign ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.fujiang_delete_campaign_title)) },
            text = { Text(stringResource(R.string.fujiang_delete_campaign_message)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDelete(campaign.id)
                        pendingDelete = null
                    }
                ) { Text(stringResource(R.string.common_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) {
                    Text(stringResource(R.string.common_cancel))
                }
            }
        )
    }
}

@Composable
private fun FindingDetailDialog(
    finding: VulnFinding,
    onDismiss: () -> Unit,
    onDelete: () -> Unit
) {
    FujiangDialog(title = finding.title.ifBlank { finding.target }, onDismiss = onDismiss, onDelete = onDelete) {
        InfoLine(stringResource(R.string.fujiang_label_severity), finding.severity)
        InfoLine(
            stringResource(R.string.fujiang_label_status),
            finding.status + " · " + stringResource(
                if (finding.verified) R.string.fujiang_verified else R.string.fujiang_unverified
            )
        )
        InfoLine(stringResource(R.string.fujiang_label_target), finding.target)
        InfoLine(stringResource(R.string.fujiang_label_url), finding.url)
        InfoLine(stringResource(R.string.fujiang_label_category), finding.category)
        InfoLine(stringResource(R.string.fujiang_label_cve), finding.cve)
        InfoLine(stringResource(R.string.fujiang_label_cvss), finding.cvss?.toString().orEmpty())
        InfoLine(stringResource(R.string.fujiang_label_description), finding.description)
        InfoLine(stringResource(R.string.fujiang_label_evidence), finding.evidence)
        InfoLine(stringResource(R.string.fujiang_label_remediation), finding.remediation)
        InfoLine(stringResource(R.string.fujiang_label_references), finding.references)
    }
}

@Composable
private fun EntryDetailDialog(
    entry: KnowledgeIndex.Entry,
    viewModel: FujiangViewModel,
    onDismiss: () -> Unit
) {
    var content by remember(entry.path) { mutableStateOf<String?>(null) }
    LaunchedEffect(entry.path) { content = viewModel.readEntry(entry.path) }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(Radius.lg),
            color = MaterialTheme.semanticColors.cardSurface
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(Spacing.lg),
                verticalArrangement = Arrangement.spacedBy(Spacing.sm)
            ) {
                Text(text = entry.title, style = MaterialTheme.typography.titleMedium)
                Text(
                    text = listOf(entry.cve, entry.severity, entry.product)
                        .filter { it.isNotBlank() && it != "无" }
                        .joinToString(" · "),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.semanticColors.subtleText
                )
                val body = content
                if (body == null) {
                    Text(
                        text = stringResource(R.string.fujiang_loading_entry),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.semanticColors.subtleText
                    )
                } else {
                    MarkdownContent(
                        text = body,
                        color = MaterialTheme.colorScheme.onSurface,
                        lazyScroll = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(max = 480.dp)
                    )
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_close)) }
                }
            }
        }
    }
}

@Composable
private fun CampaignDetailDialog(
    campaign: Campaign,
    onDismiss: () -> Unit,
    onDelete: () -> Unit
) {
    FujiangDialog(title = campaign.name, onDismiss = onDismiss, onDelete = onDelete) {
        InfoLine(
            stringResource(R.string.fujiang_label_status),
            stringResource(
                R.string.fujiang_stage_progress,
                campaign.stage,
                campaign.rounds,
                campaign.maxRounds
            )
        )
        InfoLine(stringResource(R.string.fujiang_label_objective), campaign.objective)
        val scope = campaign.scope
        InfoLine(
            stringResource(R.string.fujiang_label_scope),
            (scope.domains + scope.cidrs + scope.exclude.map { "!$it" }).joinToString(", ")
        )
        if (campaign.assets.isNotEmpty()) {
            InfoLine(stringResource(R.string.fujiang_label_assets), "")
            campaign.assets.forEach { asset ->
                Text(
                    text = "· ${asset.host}${if (asset.port > 0) ":${asset.port}" else ""} " +
                        "${asset.status}${if (asset.fingerprint.isNotBlank()) " · ${asset.fingerprint}" else ""}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.semanticColors.subtleText
                )
            }
        }
        if (campaign.steps.isNotEmpty()) {
            InfoLine(stringResource(R.string.fujiang_label_steps), "")
            campaign.steps.takeLast(20).forEach { step ->
                Text(
                    text = "· [${step.stage}] ${step.command}".trim().let {
                        if (step.result.isBlank()) it else "$it → ${step.result}"
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.semanticColors.subtleText
                )
            }
        }
        if (campaign.attempts.isNotEmpty()) {
            InfoLine(stringResource(R.string.fujiang_label_attempts), "")
            campaign.attempts.takeLast(20).forEach { attempt ->
                Text(
                    text = "· ${attempt.kb} ${attempt.outcome} ${attempt.note}".trim(),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.semanticColors.subtleText
                )
            }
        }
    }
}

/** 详情弹窗骨架：标题 + 可滚动正文 + 删除/关闭。 */
@Composable
private fun FujiangDialog(
    title: String,
    onDismiss: () -> Unit,
    onDelete: () -> Unit,
    content: @Composable () -> Unit
) {
    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = RoundedCornerShape(Radius.lg),
            color = MaterialTheme.semanticColors.cardSurface
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(Spacing.lg),
                verticalArrangement = Arrangement.spacedBy(Spacing.sm)
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Column(
                    modifier = Modifier
                        .heightIn(max = 480.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(Spacing.xs)
                ) {
                    content()
                }
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = onDelete) {
                        Text(
                            text = stringResource(R.string.common_delete),
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                    Spacer(modifier = Modifier.width(Spacing.sm))
                    TextButton(onClick = onDismiss) { Text(stringResource(R.string.common_close)) }
                }
            }
        }
    }
}

@Composable
private fun InfoLine(label: String, value: String) {
    if (value.isBlank()) return
    Row(modifier = Modifier.fillMaxWidth()) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.semanticColors.subtleText,
            modifier = Modifier.width(72.dp)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}
