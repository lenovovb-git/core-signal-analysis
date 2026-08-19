"""
主Agent模块 - 协调各模块完成分析任务
"""
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

from .packet_parser import parse_packet, parse_context
from .normalizer import normalize_packet
from .rule_engine import RuleEngine
from .case_store import CaseStore
from .llm_client import LLMClient
from .config import settings


logger = logging.getLogger(__name__)


class CoreSignalAgent:
    """核心网信令分析Agent"""
    
    def __init__(
        self,
        rules_dir: Optional[str] = None,
        case_db_path: Optional[str] = None,
        llm_config: Optional[Dict] = None,
        use_llm: bool = True
    ):
        """
        初始化Agent
        
        Args:
            rules_dir: 规则目录路径
            case_db_path: 案例数据库路径
            llm_config: LLM配置
            use_llm: 是否使用LLM
        """
        self.rule_engine = RuleEngine(rules_dir)
        self.case_store = CaseStore(case_db_path)
        self.llm_client = LLMClient(llm_config) if use_llm else None
        self.use_llm = use_llm
        
        logger.info("核心网信令分析Agent已初始化")
    
    def analyze(
        self,
        pcap_path: str,
        frame_number: int,
        window: Optional[int] = None,
        match_mode: str = "exact",
        user_notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        执行完整分析流程
        
        Args:
            pcap_path: pcap文件路径
            frame_number: 目标帧号
            window: 上下文窗口大小
            match_mode: 规则匹配模式
            user_notes: 用户补充信息
            
        Returns:
            分析结果
        """
        logger.info(f"开始分析: {pcap_path} 帧号 {frame_number}")
        
        # 1. 解析目标报文
        try:
            selected_packet = parse_packet(pcap_path, frame_number)
            logger.info(f"目标报文解析成功: {selected_packet.get('frame_number')}")
        except Exception as e:
            logger.error(f"目标报文解析失败: {e}")
            raise
        
        # 2. 解析上下文报文
        try:
            related_packets = parse_context(pcap_path, frame_number, window)
            logger.info(f"上下文报文解析成功: {len(related_packets)}条")
        except Exception as e:
            logger.error(f"上下文报文解析失败: {e}")
            related_packets = []
        
        # 3. 标准化目标报文
        try:
            normalized_packet = normalize_packet(selected_packet, selected_packet.get("raw_packet"))
            logger.info(f"报文标准化成功: {normalized_packet.get('protocol')}")
        except Exception as e:
            logger.error(f"报文标准化失败: {e}")
            normalized_packet = {}
        
        # 4. 匹配专家规则
        try:
            matched_rules = self.rule_engine.match_rules(normalized_packet, match_mode)
            logger.info(f"规则匹配成功: {len(matched_rules)}条")
        except Exception as e:
            logger.error(f"规则匹配失败: {e}")
            matched_rules = []
        
        # 5. 检索相似案例
        try:
            similar_cases = self.case_store.search_similar(normalized_packet, limit=5)
            logger.info(f"案例检索成功: {len(similar_cases)}个")
        except Exception as e:
            logger.error(f"案例检索失败: {e}")
            similar_cases = []
        
        # 6. 构建分析上下文
        context = {
            "selected_packet": selected_packet,
            "related_packets": related_packets,
            "normalized_packet": normalized_packet,
            "matched_rules": matched_rules,
            "similar_cases": similar_cases,
            "user_notes": user_notes,
            "analysis_config": {
                "pcap_path": pcap_path,
                "frame_number": frame_number,
                "window": window or settings.default_window,
                "match_mode": match_mode,
                "use_llm": self.use_llm,
            }
        }
        
        # 7. 生成分析报告
        try:
            if self.llm_client and self.use_llm:
                analysis_report = self.llm_client.generate_analysis_report(context)
            else:
                analysis_report = self.llm_client.generate_analysis_report(context, use_llm=False) if self.llm_client else None
                if not analysis_report:
                    # 创建简单的规则库报告
                    analysis_report = {
                        "content": self._generate_simple_report(context),
                        "format": "markdown",
                        "is_rule_based": True,
                        "generated_at": self._get_timestamp()
                    }
            logger.info("分析报告生成成功")
        except Exception as e:
            logger.error(f"分析报告生成失败: {e}")
            analysis_report = {
                "content": f"报告生成失败: {str(e)}",
                "format": "text",
                "is_error": True,
                "generated_at": self._get_timestamp()
            }
        
        # 8. 构建最终结果
        result = {
            "analysis_id": self._generate_analysis_id(),
            "timestamp": self._get_timestamp(),
            "context": context,
            "analysis_report": analysis_report,
            "summary": self._generate_summary(context, analysis_report)
        }
        
        logger.info(f"分析完成: ID {result['analysis_id']}")
        return result
    
    def save_as_case(
        self,
        analysis_result: Dict[str, Any],
        title: str,
        root_cause: str,
        solution: str,
        evidence: Optional[str] = None,
        tags: Optional[List[str]] = None
    ) -> int:
        """
        将分析结果保存为历史案例
        
        Args:
            analysis_result: 分析结果
            title: 案例标题
            root_cause: 根因分析
            solution: 解决方案
            evidence: 证据说明
            tags: 标签列表
            
        Returns:
            案例ID
        """
        context = analysis_result.get("context", {})
        normalized = context.get("normalized_packet", {})
        
        case_data = {
            "title": title,
            "domain": normalized.get("access_type", ""),
            "protocol": normalized.get("protocol", ""),
            "procedure_name": normalized.get("procedure", ""),
            "message_type": normalized.get("message_type", ""),
            "cause_category": normalized.get("cause_category", ""),
            "cause_value": normalized.get("cause_value", ""),
            "symptoms": self._extract_symptoms(context),
            "root_cause": root_cause,
            "solution": solution,
            "evidence": evidence or self._extract_evidence(context),
            "tags": tags or []
        }
        
        case_id = self.case_store.save_case(case_data)
        logger.info(f"案例已保存: {title} (ID: {case_id})")
        return case_id
    
    def generate_rule_draft(
        self,
        analysis_result: Dict[str, Any],
        title: str,
        possible_causes: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        从分析结果生成规则草稿
        
        Args:
            analysis_result: 分析结果
            title: 规则标题
            possible_causes: 可能原因列表
            
        Returns:
            规则草稿
        """
        context = analysis_result.get("context", {})
        normalized = context.get("normalized_packet", {})
        
        rule_draft = {
            "id": self._generate_rule_id(normalized, title),
            "title": title,
            "domain": normalized.get("access_type", ""),
            "protocol": normalized.get("protocol", ""),
            "match": {
                "procedure": normalized.get("procedure", ""),
                "message_type": normalized.get("message_type", ""),
                "result": normalized.get("result", ""),
                "cause_category": normalized.get("cause_category", ""),
                "cause_value": normalized.get("cause_value", ""),
            },
            "possible_causes": possible_causes,
            "missing_info": self._extract_missing_info(context),
            "created_from_analysis": analysis_result.get("analysis_id", ""),
            "created_at": self._get_timestamp()
        }
        
        logger.info(f"规则草稿已生成: {title}")
        return rule_draft
    
    def add_rule_draft(self, rule_draft: Dict[str, Any]) -> None:
        """
        添加规则草稿到规则库
        
        Args:
            rule_draft: 规则草稿
        """
        protocol = rule_draft.get("protocol", "").lower()
        if not protocol:
            logger.error("规则草稿缺少protocol字段")
            return
        
        self.rule_engine.add_rule(rule_draft, protocol)
        self.rule_engine.save_rules(protocol)
        logger.info(f"规则草稿已添加到规则库: {rule_draft.get('title')}")
    
    def _generate_simple_report(self, context: Dict[str, Any]) -> str:
        """生成简单的报告（无LLM时使用）"""
        normalized = context.get("normalized_packet", {})
        matched_rules = context.get("matched_rules", [])
        
        report = f"""# 核心网信令分析报告（规则库模式）

## 基本信息
- 协议: {normalized.get('protocol', 'N/A')}
- 消息类型: {normalized.get('message_type', 'N/A')}
- 结果: {normalized.get('result', 'N/A')}
- Cause: {normalized.get('cause_category', 'N/A')}:{normalized.get('cause_value', 'N/A')}

## 匹配的专家规则 ({len(matched_rules)}条)
"""
        
        if matched_rules:
            for i, rule in enumerate(matched_rules[:3], 1):
                report += f"""
{i}. **{rule.get('title', '未命名规则')}** (匹配度: {rule.get('score', 0):.2f})
"""
                
                possible_causes = rule.get("possible_causes", [])
                if possible_causes:
                    for cause in possible_causes[:2]:
                        report += f"   - {cause.get('title', '')}\n"
        else:
            report += "\n未匹配到专家规则。\n"
        
        report += f"""
## 建议
1. 检查相关网元配置
2. 查看前后信令流程
3. 对比正常流程报文
4. 考虑保存为历史案例供后续参考

*注：当前为规则库模式，如需更详细分析请配置LLM。*
"""
        
        return report
    
    def _generate_summary(
        self,
        context: Dict[str, Any],
        analysis_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """生成摘要信息"""
        normalized = context.get("normalized_packet", {})
        matched_rules = context.get("matched_rules", [])
        similar_cases = context.get("similar_cases", [])
        
        return {
            "protocol": normalized.get("protocol", ""),
            "message_type": normalized.get("message_type", ""),
            "result": normalized.get("result", ""),
            "cause": f"{normalized.get('cause_category', '')}:{normalized.get('cause_value', '')}",
            "matched_rules_count": len(matched_rules),
            "similar_cases_count": len(similar_cases),
            "report_type": "llm" if analysis_report.get("is_rule_based") is False else "rule_based",
            "has_error": analysis_report.get("is_error", False)
        }
    
    def _extract_symptoms(self, context: Dict[str, Any]) -> str:
        """提取症状描述"""
        normalized = context.get("normalized_packet", {})
        selected = context.get("selected_packet", {})
        
        symptoms = []
        if normalized.get("protocol"):
            symptoms.append(f"协议: {normalized['protocol']}")
        if normalized.get("message_type"):
            symptoms.append(f"消息类型: {normalized['message_type']}")
        if normalized.get("result") == "failure":
            symptoms.append("结果: 失败")
        cause = f"{normalized.get('cause_category', '')}:{normalized.get('cause_value', '')}"
        if ":" in cause and cause != ":":
            symptoms.append(f"失败原因: {cause}")
        
        return "; ".join(symptoms)
    
    def _extract_evidence(self, context: Dict[str, Any]) -> str:
        """提取证据信息"""
        selected = context.get("selected_packet", {})
        normalized = context.get("normalized_packet", {})
        
        evidence = []
        if selected.get("frame_number"):
            evidence.append(f"帧号: {selected['frame_number']}")
        if normalized.get("protocol"):
            evidence.append(f"协议: {normalized['protocol']}")
        if normalized.get("message_type"):
            evidence.append(f"消息类型: {normalized['message_type']}")
        
        return "; ".join(evidence)
    
    def _extract_missing_info(self, context: Dict[str, Any]) -> List[str]:
        """提取缺失信息"""
        normalized = context.get("normalized_packet", {})
        missing = []
        
        if not normalized.get("cause_value"):
            missing.append("具体的Cause值")
        if not normalized.get("procedure"):
            missing.append("完整的信令流程")
        if not normalized.get("ue_identifiers"):
            missing.append("UE标识信息")
        if not normalized.get("network_context"):
            missing.append("网络上下文信息")
        
        return missing
    
    def _generate_analysis_id(self) -> str:
        """生成分析ID"""
        import uuid
        return f"analysis_{uuid.uuid4().hex[:8]}"
    
    def _generate_rule_id(self, normalized: Dict[str, Any], title: str) -> str:
        """生成规则ID"""
        import hashlib
        
        base_str = f"{normalized.get('protocol', '')}_{normalized.get('message_type', '')}_{title}"
        hash_obj = hashlib.md5(base_str.encode())
        return f"rule_{hash_obj.hexdigest()[:8]}"
    
    def _get_timestamp(self) -> str:
        """获取时间戳"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def close(self) -> None:
        """关闭Agent"""
        if self.llm_client:
            self.llm_client.close()
        logger.info("Agent已关闭")