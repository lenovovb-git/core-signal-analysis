"""
测试：信令标准化模块
"""
import pytest
from app.normalizer import (
    _identify_access_type,
    _identify_top_protocol,
    _infer_result,
    _match_ngap_message,
    _match_nas5gs_message,
)


class TestNormalizer:
    """标准化模块测试"""
    
    def test_identify_access_type_5g(self):
        protocols = ["sctp", "ngap", "nas-5gs"]
        result = _identify_access_type(protocols)
        assert result == "5G"
    
    def test_identify_access_type_4g(self):
        protocols = ["s1ap", "nas-eps", "gtpv2"]
        result = _identify_access_type(protocols)
        assert result == "4G"
    
    def test_identify_access_type_ims(self):
        protocols = ["sip", "diameter"]
        result = _identify_access_type(protocols)
        assert result == "IMS"
    
    def test_identify_access_type_none(self):
        protocols = ["tcp", "http"]
        result = _identify_access_type(protocols)
        assert result is None
    
    def test_identify_top_protocol_ngap(self):
        protocols = ["sctp", "ngap"]
        result = _identify_top_protocol(protocols)
        assert result == "NGAP"
    
    def test_identify_top_protocol_nas5gs(self):
        protocols = ["nas-5gs"]
        result = _identify_top_protocol(protocols)
        assert result == "NAS-5GS"
    
    def test_identify_top_protocol_none(self):
        protocols = ["tcp", "http"]
        result = _identify_top_protocol(protocols)
        assert result is None
    
    def test_infer_result_failure(self):
        result = _infer_result("RegistrationReject", "15")
        assert result == "failure"
    
    def test_infer_result_success(self):
        result = _infer_result("RegistrationAccept", None)
        assert result == "success"
    
    def test_match_ngap_message_pdu_session_setup(self):
        info = "PDUSessionResourceSetupResponse"
        result = _match_ngap_message(info)
        assert result is not None
        assert result["procedure"] == "PDU Session Resource Setup"
        assert result["message_type"] == "PDUSessionResourceSetupResponse"
    
    def test_match_ngap_message_context_setup_failure(self):
        info = "Initial Context Setup Failure"
        result = _match_ngap_message(info)
        assert result is not None
        assert result["procedure"] == "Initial Context Setup"
        assert result["message_type"] == "InitialContextSetupFailure"
    
    def test_match_nas5gs_registration_reject(self):
        info = "Registration reject"
        result = _match_nas5gs_message(info)
        assert result is not None
        assert result["procedure"] == "Registration"
        assert result["message_type"] == "RegistrationReject"
    
    def test_match_nas5gs_pdu_session_reject(self):
        info = "PDU session establishment reject"
        result = _match_nas5gs_message(info)
        assert result is not None
        assert result["procedure"] == "PDU Session Establishment"
        assert result["message_type"] == "PDUSessionEstablishmentReject"