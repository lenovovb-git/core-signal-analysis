"""
测试：抓包解析模块
"""
import pytest
import tempfile
from pathlib import Path
import subprocess
from app.packet_parser import test_tshark_available


class TestPacketParser:
    """抓包解析模块测试"""
    
    def test_tshark_available(self):
        """测试tshark是否可用"""
        # 这个测试依赖于系统环境
        # 如果tshark不可用，测试会跳过
        try:
            result = test_tshark_available()
            # 不检查具体结果，因为不同环境不同
            assert isinstance(result, bool)
        except Exception as e:
            pytest.skip(f"tshark测试失败: {e}")
    
    def test_extract_protocols(self):
        """测试协议栈提取"""
        from app.packet_parser import extract_protocols
        
        layers = {
            "frame": {"frame.number": "1"},
            "sctp": {"sctp.srcport": "38412"},
            "ngap": {"ngap.ProcedureCode": "12"},
            "nas-5gs": {"nas_5gs.message_type": "0x41"},
            "_ws.col.Info": "Test Info"
        }
        
        protocols = extract_protocols(layers)
        assert "frame" in protocols
        assert "sctp" in protocols
        assert "ngap" in protocols
        assert "nas-5gs" in protocols
        assert "_ws.col.Info" not in protocols  # 排除内部字段
        assert len(protocols) == 4
    
    def test_extract_protocols_empty(self):
        """测试空协议栈提取"""
        from app.packet_parser import extract_protocols
        
        layers = {}
        protocols = extract_protocols(layers)
        assert protocols == []
    
    def test_extract_protocols_only_frame(self):
        """测试只有frame层的情况"""
        from app.packet_parser import extract_protocols
        
        layers = {
            "frame": {"frame.number": "1"},
            "_ws.col.Info": "Test Info"
        }
        
        protocols = extract_protocols(layers)
        assert protocols == ["frame"]