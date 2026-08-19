"""
LLM客户端模块 - 调用大模型生成分析报告
"""
import json
import logging
from typing import Dict, List, Optional, Any
import httpx

from .config import get_llm_config


logger = logging.getLogger(__name__)


class LLMClient:
    """LLM客户端"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        初始化LLM客户端
        
        Args:
            config: LLM配置，默认使用全局配置
        """
        self.config = config or get_llm_config()
        self.client = None
        self._init_client()
    
    def _init_client(self) -> None:
        """初始化HTTP客户端"""
        headers = {
            "Content-Type": "application/json",
        }
        
        if self.config.get("api_key"):
            headers["Authorization"] = f"Bearer {self.config['api_key']}"
        
        self.client = httpx.Client(
            base_url=self.config.get("base_url"),
            headers=headers,
            timeout=60.0
        )
    
    def generate_analysis_report(
        self,
        context: Dict[str, Any],
        use_llm: bool = True
    ) -> Dict[str, Any]:
        """
        生成分析报告
        
        Args:
            context: 分析上下文
            use_llm: 是否使用LLM，False时只使用规则库
            
        Returns:
            分析报告
        """
        if not use_llm or not self.config.get("api_key"):
            return self._generate_rule_based_report(context)
        
        try:
            return self._call_llm_for_report(context)
        except Exception as e:
            logger.error(f"LLM调用失败: {e}")
            return self._generate_rule_based_report(context)
    
    def _call_llm_for_report(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """调用LLM生成报告"""
        prompt = self._build_analysis_prompt(context)
        
        messages = [
            {
                "role": "system",
                "content": self._get_system_prompt()
            },
            {
                "role": "user",
                "content": prompt
            }
        ]
        
        response = self.client.post(
            "/chat/completions",
            json={
                "model": self.config.get("model", "gpt-4o-mini"),
                "messages": messages,
                "temperature": 0.1,
                "max_tokens": 2000
            }
        )
        
        if response.status_code != 200:
            raise RuntimeError(f"LLM API错误: {response.status_code} - {response.text}")
        
        result = response.json()
        content = result["choices"][0]["message"]["content"]
        
        # 解析LLM输出
        return self._parse_llm_output(content, context)
    
    def _build_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """构建分析提示词"""
        selected_packet = context.get("selected_packet", {})
        normalized = context.get("normalized_packet", {})
        matched_rules = context.get("matched_rules", [])
        similar_cases = context.get("similar_cases", [])
        related_packets = context.get("related_packets", [])
        
        prompt = f"""请分析以下核心网信令失败场景，生成结构化的排障报告。

## 目标报文信息
- 帧号: {selected_packet.get('frame_number', 'N/A')}
- 时间戳: {selected_packet.get('timestamp', 'N/A')}
- 协议栈: {', '.join(selected_packet.get('protocols', []))}
- 原始信息: {selected_packet.get('info', '')}

## 标准化信息
- 接入类型: {normalized.get('access_type', 'N/A')}
- 协议: {normalized.get('protocol', 'N/A')}
- 流程: {normalized.get('procedure', 'N/A')}
- 消息类型: {normalized.get('message_type', 'N/A')}
- 结果: {normalized.get('result', 'N/A')}
- Cause类别: {normalized.get('cause_category', 'N/A')}
- Cause值: {normalized.get('cause_value', 'N/A')}

## 匹配的专家规则 ({len(matched_rules)}条)
"""
        
        for i, rule in enumerate(matched_rules[:3], 1):
            prompt += f"""
{i}. {rule.get('title', '未命名规则')}
   - 匹配分数: {rule.get('score', 0):.2f}
   - 可能原因: {len(rule.get('possible_causes', []))}个
   - 证据: {', '.join(rule.get('matched_fields', []))}
"""
        
        prompt += f"""
## 相似历史案例 ({len(similar_cases)}个)
"""
        
        for i, case in enumerate(similar_cases[:3], 1):
            prompt += f"""
{i}. {case.get('title', '未命名案例')}
   - 协议: {case.get('protocol', 'N/A')}
   - 根因: {case.get('root_cause', 'N/A')}
   - 解决方案: {case.get('solution', 'N/A')}
"""
        
        prompt += f"""
## 相关上下文报文 ({len(related_packets)}条)
"""
        
        for i, pkt in enumerate(related_packets[:5], 1):
            is_target = "✓" if pkt.get("is_target") else " "
            prompt += f"""
{is_target} {pkt.get('frame_number', 'N/A')}: {pkt.get('protocols', [])} - {pkt.get('info', '')}
"""
        
        prompt += """

## 分析要求
请基于以上信息，生成结构化的排障报告，必须包含以下章节：

1. **结论** (最可能的原因总结)
2. **关键证据** (从报文中确认的事实)
3. **可能原因排序** (按可能性高到低排序，每个原因必须说明证据或缺失证据)
4. **需要进一步确认的信息** (哪些信息缺失，需要检查什么)
5. **建议排查步骤** (具体的检查项和顺序)
6. **可沉淀为知识库的内容** (本次分析可以提炼出什么新规则或案例)

请确保：
- 每个结论都有依据（来自报文、规则或案例）
- 区分已确认事实和推测
- 不确定时明确说明需要补充什么信息
- 避免泛泛而谈的建议
- 输出为Markdown格式
"""
        
        return prompt
    
    def _get_system_prompt(self) -> str:
        """获取系统提示词"""
        return """你是一个核心网信令分析专家，专门分析4G/5G/IMS信令失败原因。

你的职责：
1. 基于提供的报文信息、专家规则和历史案例进行分析
2. 输出结构化的排障报告
3. 每个结论必须有明确的证据来源
4. 区分已确认事实和推测
5. 不确定时提出具体的补充检查项

分析原则：
- 优先考虑匹配的专家规则
- 参考相似历史案例
- 结合协议规范分析
- 考虑网元配置、参数错误、网络问题等多方面原因
- 输出具体可操作的排查建议

输出格式：
必须使用Markdown格式，包含指定的章节结构。"""
    
    def _parse_llm_output(self, content: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """解析LLM输出"""
        return {
            "content": content,
            "format": "markdown",
            "context_summary": {
                "matched_rules_count": len(context.get("matched_rules", [])),
                "similar_cases_count": len(context.get("similar_cases", [])),
                "related_packets_count": len(context.get("related_packets", [])),
            },
            "generated_at": self._get_timestamp()
        }
    
    def _generate_rule_based_report(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """生成基于规则库的报告（无LLM时使用）"""
        normalized = context.get("normalized_packet", {})
        matched_rules = context.get("matched_rules", [])
        similar_cases = context.get("similar_cases", [])
        
        # 构建基础报告
        report_parts = []
        
        # 1. 结论
        if matched_rules:
            top_rule = matched_rules[0]
            report_parts.append("## 结论\n")
            report_parts.append(f"最可能与 **{top_rule.get('title', '未知原因')}** 相关。\n")
        else:
            report_parts.append("## 结论\n")
            report_parts.append("未匹配到明确的专家规则，需要进一步分析。\n")
        
        # 2. 关键证据
        report_parts.append("## 关键证据\n")
        evidence_items = []
        
        if normalized.get("protocol"):
            evidence_items.append(f"- 协议: {normalized['protocol']}")
        if normalized.get("message_type"):
            evidence_items.append(f"- 消息类型: {normalized['message_type']}")
        if normalized.get("cause_category") or normalized.get("cause_value"):
            cause_str = f"{normalized.get('cause_category', '')}:{normalized.get('cause_value', '')}"
            evidence_items.append(f"- Cause: {cause_str}")
        
        if evidence_items:
            report_parts.append("\n".join(evidence_items) + "\n")
        else:
            report_parts.append("- 无明确的失败原因字段\n")
        
        # 3. 可能原因排序
        report_parts.append("## 可能原因排序\n")
        
        if matched_rules:
            for i, rule in enumerate(matched_rules[:3], 1):
                report_parts.append(f"### {i}. {rule.get('title', '未知规则')}\n")
                
                possible_causes = rule.get("possible_causes", [])
                if possible_causes:
                    for cause in possible_causes[:2]:
                        confidence = cause.get("confidence", "medium")
                        title = cause.get("title", "")
                        report_parts.append(f"- **{confidence.upper()}** {title}\n")
                else:
                    report_parts.append("- 无具体原因说明\n")
        else:
            report_parts.append("未匹配到专家规则，无法提供可能原因排序。\n")
        
        # 4. 需要进一步确认的信息
        report_parts.append("## 需要进一步确认的信息\n")
        missing_info = []
        
        if not normalized.get("cause_value"):
            missing_info.append("- 具体的Cause值")
        if not normalized.get("procedure"):
            missing_info.append("- 完整的信令流程")
        if not similar_cases:
            missing_info.append("- 相似历史案例")
        
        if missing_info:
            report_parts.append("\n".join(missing_info) + "\n")
        else:
            report_parts.append("- 基础信息完整，可进行进一步分析\n")
        
        # 5. 建议排查步骤
        report_parts.append("## 建议排查步骤\n")
        report_parts.append("1. 检查相关网元的配置和状态\n")
        report_parts.append("2. 查看前后相关信令消息\n")
        report_parts.append("3. 对比正常流程的报文\n")
        report_parts.append("4. 检查网络连接和传输质量\n")
        
        # 6. 可沉淀为知识库的内容
        report_parts.append("## 可沉淀为知识库的内容\n")
        if matched_rules:
            report_parts.append("本次分析匹配了现有专家规则，可考虑：\n")
            report_parts.append("- 更新规则的匹配条件\n")
            report_parts.append("- 补充新的可能原因\n")
        else:
            report_parts.append("本次分析未匹配现有规则，可考虑：\n")
            report_parts.append("- 创建新的专家规则\n")
            report_parts.append("- 保存为历史案例\n")
        
        content = "\n".join(report_parts)
        
        return {
            "content": content,
            "format": "markdown",
            "is_rule_based": True,
            "context_summary": {
                "matched_rules_count": len(matched_rules),
                "similar_cases_count": len(similar_cases),
            },
            "generated_at": self._get_timestamp()
        }
    
    def _get_timestamp(self) -> str:
        """获取时间戳"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def close(self) -> None:
        """关闭客户端"""
        if self.client:
            self.client.close()