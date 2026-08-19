"""
专家规则引擎 - 加载和匹配YAML规则库
"""
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
import yaml

from .config import settings


logger = logging.getLogger(__name__)


class RuleEngine:
    """专家规则引擎"""
    
    def __init__(self, rules_dir: Optional[str] = None):
        """
        初始化规则引擎
        
        Args:
            rules_dir: 规则目录路径，默认使用配置
        """
        self.rules_dir = Path(rules_dir) if rules_dir else settings.rules_dir
        self.rules: Dict[str, List[Dict]] = {}
        self._load_rules()
    
    def _load_rules(self) -> None:
        """加载所有规则文件"""
        self.rules = {}
        
        if not self.rules_dir.exists():
            logger.warning(f"规则目录不存在: {self.rules_dir}")
            return
        
        for yaml_file in self.rules_dir.glob("*.yaml"):
            try:
                with open(yaml_file, "r", encoding="utf-8") as f:
                    rules = yaml.safe_load(f)
                    if rules:
                        # 处理文件名到协议名的映射
                        filename = yaml_file.stem.lower()
                        if filename == "nas_5gs":
                            protocol = "NAS-5GS"
                        elif filename == "ngap":
                            protocol = "NGAP"
                        else:
                            protocol = filename.upper()
                        
                        self.rules[protocol] = rules
                        logger.info(f"加载规则文件: {yaml_file.name} ({len(rules)}条规则)")
            except Exception as e:
                logger.error(f"加载规则文件失败 {yaml_file}: {e}")
    
    def reload(self) -> None:
        """重新加载所有规则"""
        self._load_rules()
    
    def match_rules(
        self,
        normalized_packet: Dict[str, Any],
        match_mode: str = "exact"
    ) -> List[Dict[str, Any]]:
        """
        匹配专家规则
        
        Args:
            normalized_packet: 标准化后的报文
            match_mode: 匹配模式 - exact(精确) / fuzzy(模糊)
            
        Returns:
            匹配的规则列表
        """
        matched = []
        protocol = normalized_packet.get("protocol", "")
        
        # 获取对应协议的规则
        protocol_rules = self.rules.get(protocol, [])
        if not protocol_rules:
            # 尝试全量匹配
            for rules in self.rules.values():
                matched.extend(self._match_rule_set(
                    rules, normalized_packet, match_mode
                ))
        else:
            matched = self._match_rule_set(
                protocol_rules, normalized_packet, match_mode
            )
        
        return matched
    
    def _match_rule_set(
        self,
        rules: List[Dict],
        packet: Dict[str, Any],
        match_mode: str
    ) -> List[Dict[str, Any]]:
        """匹配一组规则"""
        matched = []
        
        for rule in rules:
            match_conditions = rule.get("match", {})
            if not match_conditions:
                continue
            
            score = self._calculate_match_score(match_conditions, packet, match_mode)
            
            if score > 0:
                matched.append({
                    "rule": rule,
                    "score": score,
                    "matched_fields": self._get_matched_fields(match_conditions, packet),
                    **rule
                })
        
        # 按匹配分数排序
        matched.sort(key=lambda x: x["score"], reverse=True)
        return matched
    
    def _calculate_match_score(
        self,
        conditions: Dict[str, Any],
        packet: Dict[str, Any],
        match_mode: str
    ) -> float:
        """计算匹配分数"""
        score = 0.0
        weights = {
            "procedure": 3.0,
            "message_type": 3.0,
            "result": 2.0,
            "cause_category": 2.0,
            "cause_value": 2.0,
            "protocol": 1.0,
            "access_type": 1.0,
        }
        total_weight = 0.0
        
        for field, expected_value in conditions.items():
            actual_value = packet.get(field)
            
            if actual_value is None:
                continue
            
            weight = weights.get(field, 1.0)
            total_weight += weight
            
            if match_mode == "exact":
                if str(actual_value).lower() == str(expected_value).lower():
                    score += weight
            elif match_mode == "fuzzy":
                if self._fuzzy_match(str(actual_value), str(expected_value)):
                    score += weight * 0.8
            else:
                if str(actual_value).lower() == str(expected_value).lower():
                    score += weight
        
        # 归一化
        if total_weight > 0:
            score = score / total_weight
        
        return score
    
    def _fuzzy_match(self, actual: str, expected: str) -> bool:
        """模糊匹配"""
        actual_lower = actual.lower()
        expected_lower = expected.lower()
        
        if expected_lower in actual_lower:
            return True
        if actual_lower in expected_lower:
            return True
        
        # 简单的相似度匹配
        if len(set(actual_lower) & set(expected_lower)) / max(len(set(expected_lower)), 1) > 0.6:
            return True
        
        return False
    
    def _get_matched_fields(
        self,
        conditions: Dict[str, Any],
        packet: Dict[str, Any]
    ) -> List[str]:
        """获取匹配的字段"""
        matched = []
        for field in conditions:
            if field in packet and packet[field]:
                matched.append(f"{field}={packet[field]}")
        return matched
    
    def add_rule(self, rule: Dict[str, Any], protocol: str) -> None:
        """添加新规则到规则库"""
        if protocol not in self.rules:
            self.rules[protocol] = []
        
        # 检查重复
        existing_ids = {r.get("id") for r in self.rules[protocol]}
        if rule.get("id") in existing_ids:
            # 更新已有规则
            for i, existing in enumerate(self.rules[protocol]):
                if existing.get("id") == rule["id"]:
                    self.rules[protocol][i] = rule
                    break
        else:
            self.rules[protocol].append(rule)
    
    def save_rules(self, protocol: str) -> None:
        """保存规则到文件"""
        if protocol not in self.rules:
            return
        
        # 协议名到文件名的映射
        protocol_to_filename = {
            "NAS-5GS": "nas_5gs",
            "NGAP": "ngap",
        }
        filename = protocol_to_filename.get(protocol, protocol.lower())
        file_path = self.rules_dir / f"{filename}.yaml"
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.dump(
                self.rules[protocol],
                f,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False
            )
        logger.info(f"规则已保存到: {file_path}")
    
    def get_all_rules(self) -> Dict[str, List[Dict]]:
        """获取所有规则"""
        return self.rules
    
    def get_rules_by_protocol(self, protocol: str) -> List[Dict]:
        """获取指定协议的规则"""
        return self.rules.get(protocol, [])