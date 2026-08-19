"""
测试：专家规则引擎
"""
import pytest
import tempfile
from pathlib import Path
import yaml
from app.rule_engine import RuleEngine


@pytest.fixture
def test_rules_dir():
    """创建临时规则目录"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        rules_dir = Path(tmp_dir)
        
        # 创建测试规则
        test_rules = [
            {
                "id": "test_ngap_rule_1",
                "title": "Test NGAP Rule",
                "protocol": "NGAP",
                "match": {
                    "procedure": "PDU Session Resource Setup",
                    "message_type": "PDUSessionResourceSetupResponse",
                    "result": "failure",
                    "cause_category": "radioNetwork",
                    "cause_value": "unspecified"
                },
                "possible_causes": [
                    {
                        "title": "Test Cause 1",
                        "confidence": "high"
                    }
                ]
            }
        ]
        
        with open(rules_dir / "ngap.yaml", "w") as f:
            yaml.dump(test_rules, f)
        
        yield str(rules_dir)


class TestRuleEngine:
    """规则引擎测试"""
    
    def test_load_rules(self, test_rules_dir):
        engine = RuleEngine(test_rules_dir)
        rules = engine.get_all_rules()
        assert "NGAP" in rules
        assert len(rules["NGAP"]) == 1
        assert rules["NGAP"][0]["id"] == "test_ngap_rule_1"
    
    def test_exact_match_success(self, test_rules_dir):
        engine = RuleEngine(test_rules_dir)
        packet = {
            "protocol": "NGAP",
            "procedure": "PDU Session Resource Setup",
            "message_type": "PDUSessionResourceSetupResponse",
            "result": "failure",
            "cause_category": "radioNetwork",
            "cause_value": "unspecified"
        }
        matched = engine.match_rules(packet, "exact")
        assert len(matched) == 1
        assert matched[0]["score"] > 0.9
    
    def test_exact_match_no_match(self, test_rules_dir):
        engine = RuleEngine(test_rules_dir)
        packet = {
            "protocol": "NGAP",
            "message_type": "UnknownMessage",
        }
        matched = engine.match_rules(packet, "exact")
        assert len(matched) == 0
    
    def test_fuzzy_match(self, test_rules_dir):
        engine = RuleEngine(test_rules_dir)
        packet = {
            "protocol": "NGAP",
            "procedure": "PDU Session Resource",
            "message_type": "PDUSessionResourceSetupResponse",
            "result": "failure",
            "cause_category": "radioNetwork",
            "cause_value": "unspecified"
        }
        matched = engine.match_rules(packet, "fuzzy")
        assert len(matched) == 1
    
    def test_add_rule(self, test_rules_dir):
        engine = RuleEngine(test_rules_dir)
        new_rule = {
            "id": "test_new_rule",
            "title": "New Test Rule",
            "protocol": "NGAP",
            "match": {
                "procedure": "UE Context Release",
                "result": "failure"
            }
        }
        engine.add_rule(new_rule, "NGAP")
        rules = engine.get_rules_by_protocol("NGAP")
        assert any(r["id"] == "test_new_rule" for r in rules)