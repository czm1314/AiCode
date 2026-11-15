package com.aicode.feature.settings.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aicode.feature.agent.domain.fujiang.Campaign
import com.aicode.feature.agent.domain.fujiang.CampaignStore
import com.aicode.feature.agent.domain.fujiang.VulnFinding
import com.aicode.feature.agent.domain.fujiang.VulnReportStore
import com.aicode.feature.agent.domain.skill.KnowledgeIndex
import com.aicode.feature.workspace.domain.FileAccessProvider
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

/**
 * 「设置 → 富江破甲」页的数据：漏洞报告、知识库索引、渗透作业链。
 *
 * 三块都读 AI 工具写同一份文件，页面只做展示与删除；刷新时重新扫盘，AI 刚写进去的条目立刻可见。
 */
@HiltViewModel
class FujiangViewModel @Inject constructor(
    private val vulnReportStore: VulnReportStore,
    private val campaignStore: CampaignStore,
    private val fileAccess: FileAccessProvider
) : ViewModel() {

    data class UiState(
        val findings: List<VulnFinding> = emptyList(),
        val campaigns: List<Campaign> = emptyList(),
        val entries: List<KnowledgeIndex.Entry> = emptyList(),
        val loading: Boolean = false
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch {
            _state.update { it.copy(loading = true) }
            val findings = withContext(Dispatchers.IO) { vulnReportStore.list() }
            val campaigns = withContext(Dispatchers.IO) { campaignStore.list() }
            val entries = withContext(Dispatchers.IO) { KnowledgeIndex(fileAccess).entries() }
            _state.update {
                it.copy(findings = findings, campaigns = campaigns, entries = entries, loading = false)
            }
        }
    }

    fun deleteFinding(id: String) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { vulnReportStore.delete(id) }
            refresh()
        }
    }

    fun deleteCampaign(id: String) {
        viewModelScope.launch {
            withContext(Dispatchers.IO) { campaignStore.remove(id) }
            refresh()
        }
    }

    suspend fun readEntry(path: String): String = withContext(Dispatchers.IO) {
        runCatching { fileAccess.readFile(path) }.getOrDefault("")
    }
}
