"""
信令标准化模块 - 将Wireshark原始字段转换为业务统一字段
"""
import logging
import re
from typing import Dict, List, Optional, Any

from .packet_parser import extract_protocols


logger = logging.getLogger(__name__)


# ---------- 协议识别规则 ----------

PROTOCOL_PROCEDURE_MAP = {
    "NGAP": {
        "ProcedureCode": {
            "0": {"name": "AMFConfigurationUpdate"},
            "1": {"name": "AMFStatusIndication"},
            "12": {"name": "InitialContextSetup", "messages": {
                "request": "InitialContextSetupRequest",
                "response": "InitialContextSetupResponse",
                "failure": "InitialContextSetupFailure"
            }},
            "19": {"name": "PDUSessionResourceSetup", "messages": {
                "request": "PDUSessionResourceSetupRequest",
                "response": "PDUSessionResourceSetupResponse"
            }},
            "21": {"name": "PDUSessionResourceRelease", "messages": {
                "command": "PDUSessionResourceReleaseCommand",
                "response": "PDUSessionResourceReleaseResponse"
            }},
            "23": {"name": "UEContextRelease", "messages": {
                "command": "UEContextReleaseCommand",
                "complete": "UEContextReleaseComplete"
            }},
            "24": {"name": "HandoverPreparation", "messages": {
                "required": "HandoverRequired",
                "command": "HandoverCommand",
                "preparation_failure": "HandoverPreparationFailure"
            }},
            "29": {"name": "InitialUEMessage", "messages": {
                "message": "InitialUEMessage"
            }},
            "31": {"name": "DownlinkNASTransport", "messages": {
                "message": "DownlinkNASTransport"
            }},
            "32": {"name": "UplinkNASTransport", "messages": {
                "message": "UplinkNASTransport"
            }},
        }
    },
    "S1AP": {
        "ProcedureCode": {
            "0": {"name": "InitialContextSetup", "messages": {
                "request": "InitialContextSetupRequest",
                "response": "InitialContextSetupResponse",
                "failure": "InitialContextSetupFailure"
            }},
            "5": {"name": "UEContextRelease", "messages": {
                "command": "UEContextReleaseCommand",
                "complete": "UEContextReleaseComplete"
            }},
            "12": {"name": "ERABSetup", "messages": {
                "request": "ERABSetupRequest",
                "response": "ERABSetupResponse"
            }},
            "22": {"name": "HandoverPreparation", "messages": {
                "required": "HandoverRequired",
                "command": "HandoverCommand",
                "preparation_failure": "HandoverPreparationFailure"
            }},
            "25": {"name": "InitialUEMessage", "messages": {
                "message": "InitialUEMessage"
            }},
        }
    },
    "GTPv2": {
        "message_type_map": {
            "32": "CreateSessionRequest",
            "33": "CreateSessionResponse",
            "34": "ModifyBearerRequest",
            "35": "ModifyBearerResponse",
            "36": "DeleteSessionRequest",
            "37": "DeleteSessionResponse",
            "73": "DeleteBearerCommand",
            "74": "DeleteBearerFailureIndication",
            "164": "ReleaseAccessBearersRequest",
            "165": "ReleaseAccessBearersResponse",
        }
    },
    "Diameter": {
        "command_code_map": {
            "257": "Capabilities-Exchange",
            "258": "Capabilities-Exchange-Answer",
            "275": "Device-Watchdog",
            "280": "Device-Watchdog-Answer",
            "303": "Authentication-Information",
            "304": "Authentication-Information-Answer",
            "318": "Update-Location",
            "319": "Update-Location-Answer",
            "321": "Cancel-Location",
            "322": "Cancel-Location-Answer",
        }
    },
    "PFCP": {
        "message_type_map": {
            "50": "PFCPAssociationSetupRequest",
            "51": "PFCPAssociationSetupResponse",
            "52": "PFCPSessionEstablishmentRequest",
            "53": "PFCPSessionEstablishmentResponse",
            "54": "PFCPSessionModificationRequest",
            "55": "PFCPSessionModificationResponse",
            "56": "PFCPSessionDeletionRequest",
            "57": "PFCPSessionDeletionResponse",
        }
    },
}


# ---------- Cause值映射 ----------

NGAP_CAUSE_MAP = {
    "radioNetwork": {
        "0": "unspecified",
        "1": "tx2relocoverall_expiry",
        "2": "successful_handover",
        "3": "release_due_to_ngran_generated_reason",
        "4": "release_due_to_5gc_generated_reason",
        "5": "pdu_session_resource_setup_unsuccessful",
        "6": "reject_response_from_ue",
        "10": "multiple_pdu_session_id_instances_not_allowed",
        "11": "resource_not_available_for_slice",
        "12": "ims_voice_eps_fallback_or_rat_fallback_triggered",
    },
    "transport": {
        "0": "transport_resource_unavailable",
        "1": "unspecified",
    },
    "nas": {
        "0": "normal_release",
        "1": "authentication_failure",
        "2": "deregister",
        "3": "unspecified",
    },
    "protocol": {
        "0": "transfer_syntax_error",
        "1": "abstract_syntax_error_reject",
        "2": "abstract_syntax_error_ignore_and_notify",
        "3": "message_not_compatible_with_receiver_state",
        "5": "semantic_error",
        "6": "unspecified",
    },
}


def normalize_packet(packet_info: Dict[str, Any], raw_packet: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    标准化报文
    
    Args:
        packet_info: 解析后的报文信息（来自packet_parser）
        raw_packet: 原始tshark输出（可选，用于更详细的字段提取）
        
    Returns:
        标准化后的报文
    """
    result = {
        "frame_number": packet_info.get("frame_number"),
        "timestamp": packet_info.get("timestamp"),
        "protocols": packet_info.get("protocols", []),
        "access_type": None,
        "protocol": None,
        "procedure": None,
        "message_type": None,
        "result": None,
        "cause_category": None,
        "cause_value": None,
        "ue_identifiers": {},
        "network_context": {},
        "qos": {},
        "raw_info": packet_info.get("info", "")
    }
    
    # 识别接入类型和协议
    result["access_type"] = _identify_access_type(packet_info.get("protocols", []))
    result["protocol"] = _identify_top_protocol(packet_info.get("protocols", []))
    
    # 尝试提取Cause值
    if raw_packet:
        layers = raw_packet.get("_source", {}).get("layers", {})
        cause_info = _extract_cause(layers, result.get("protocol"))
        if cause_info:
            result["cause_category"] = cause_info.get("category")
            result["cause_value"] = cause_info.get("value")
    
    # 尝试识别消息类型
    if result["protocol"]:
        msg_type = _identify_message_type(packet_info.get("protocols", []), result["protocol"], packet_info)
        if msg_type:
            result["procedure"] = msg_type.get("procedure")
            result["message_type"] = msg_type.get("message_type")
            result["result"] = _infer_result(msg_type.get("message_type", ""), result.get("cause_value"))
    
    return result


def _identify_access_type(protocols: List[str]) -> Optional[str]:
    """识别接入类型"""
    if any(p in protocols for p in ["ngap", "nas-5gs", "pfcp", "http2"]):
        return "5G"
    elif any(p in protocols for p in ["s1ap", "nas-eps", "gtpv2"]):
        return "4G"
    elif any(p in protocols for p in ["sip", "diameter"]):
        return "IMS"
    return None


def _identify_top_protocol(protocols: List[str]) -> Optional[str]:
    """识别顶层协议"""
    protocol_list = [p.lower() for p in protocols]
    
    for p in ["ngap", "s1ap", "nas-5gs", "nas-eps", "diameter", "gtpv2", "pfcp", "sip", "http2"]:
        if p in protocol_list:
            # 映射回标准名称
            return {
                "ngap": "NGAP",
                "s1ap": "S1AP",
                "nas-5gs": "NAS-5GS",
                "nas-eps": "NAS-EPS",
                "diameter": "Diameter",
                "gtpv2": "GTPv2-C",
                "pfcp": "PFCP",
                "sip": "SIP",
                "http2": "HTTP/2",
            }.get(p)
    return None


def _extract_cause(layers: Dict[str, Any], protocol: Optional[str]) -> Optional[Dict[str, str]]:
    """从layers提取Cause值"""
    # 针对S1AP提取Cause
    if protocol == "S1AP" and "s1ap" in layers:
        s1ap_layer = layers["s1ap"]
        # S1AP Cause在causeGroup和causeValue字段
        cause_group = s1ap_layer.get("s1ap.CauseGroup", "")
        cause_value = s1ap_layer.get("s1ap.CauseValue", "")
        
        if cause_group and cause_value:
            return {
                "category": cause_group.lower().replace("cause", "").strip(),
                "value": cause_value
            }
        # S1AP旧格式字段
        cause = s1ap_layer.get("s1ap.cause", "")
        if cause:
            return {
                "category": None,
                "value": cause
            }
    
    # 针对NGAP提取Cause
    if protocol == "NGAP" and "ngap" in layers:
        ngap_layer = layers["ngap"]
        cause_group = ngap_layer.get("ngap.CauseGroup", "")
        cause_value = ngap_layer.get("ngap.Cause_value", "")
        
        if cause_group and cause_value:
            return {
                "category": cause_group.lower().replace("cause", "").strip(),
                "value": cause_value
            }
    
    # 针对NAS-5GS提取Cause
    if protocol == "NAS-5GS" and "nas-5gs" in layers:
        nas_layer = layers["nas-5gs"]
        cause = nas_layer.get("nas_5gs.nmm.cause", "") or nas_layer.get("nas_5gs.5gmm.cause", "")
        if cause:
            return {
                "category": None,
                "value": cause
            }
    
    # 从Info字段尝试提取
    if "frame" in layers:
        info = layers["frame"].get("_ws.col.Info", "").lower()
        # 常见失败关键词
        for keyword in ["reject", "failure", "failed", "unsuccessful", "error"]:
            if keyword in info:
                return {
                    "category": None,
                    "value": keyword
                }
    
    return None


def _infer_result(message_type: str, cause_value: Optional[str]) -> Optional[str]:
    """从消息类型和Cause值推断结果"""
    if not message_type:
        return None
    
    msg_lower = message_type.lower()
    
    # 明确失败的消息类型
    failure_keywords = ["reject", "failure", "unsuccessful", "error"]
    for kw in failure_keywords:
        if kw in msg_lower:
            return "failure"
    
    # 成功类型
    success_keywords = ["accept", "complete", "success"]
    for kw in success_keywords:
        if kw in msg_lower:
            return "success"
    
    # 有Cause且Cause非零
    if cause_value and cause_value.lower() not in ["unspecified", "null", "0"]:
        return "failure"
    
    return None


def _identify_message_type(protocols: List[str], protocol: str, packet_info: Optional[Dict] = None) -> Optional[Dict]:
    """通过协议栈和原始数据识别消息类型"""
    # 从Info字段尝试提取
    if packet_info and packet_info.get("info"):
        info = packet_info.get("info", "")
        
        # NGAP消息模式
        if protocol == "NGAP":
            return _match_ngap_message(info)
        
        # S1AP消息模式
        if protocol == "S1AP":
            return _match_s1ap_message(info)
        
        # NAS-5GS消息模式
        if protocol == "NAS-5GS":
            return _match_nas5gs_message(info)
        
        # GTPv2消息模式
        if protocol == "GTPv2-C":
            return _match_gtpv2_message(info)
        
        # Diameter消息模式
        if protocol == "Diameter":
            return _match_diameter_message(info)
        
        # PFCP消息模式
        if protocol == "PFCP":
            return _match_pfcp_message(info)
        
        # SIP消息模式
        if protocol == "SIP":
            return _match_sip_message(info)
    
    return None


def _match_s1ap_message(info: str) -> Optional[Dict[str, str]]:
    """匹配S1AP消息类型"""
    # 初始化结果
    result = {
        "message_type": None,
        "procedure_code": None,
        "result": None
    }
    
    # S1AP消息类型模式（按最常见优先排列，避免误匹配）
    s1ap_patterns = [
        # 高频消息（tshark实际输出格式）
        (r"(?i)\bInitialUEMessage\b", {"message_type": "Initial UE Message", "procedure": "Initial UE Message"}),
        (r"(?i)\bDownlinkNASTransport\b", {"message_type": "Downlink NAS Transport", "procedure": "NAS Transport"}),
        (r"(?i)\bUplinkNASTransport\b", {"message_type": "Uplink NAS Transport", "procedure": "NAS Transport"}),
        (r"(?i)\bInitialContextSetupRequest\b", {"message_type": "Initial Context Setup Request", "procedure": "UE Context Management"}),
        (r"(?i)\bInitialContextSetupResponse\b", {"message_type": "Initial Context Setup Response", "procedure": "UE Context Management"}),
        (r"(?i)\bInitialContextSetupFailure\b", {"message_type": "Initial Context Setup Failure", "procedure": "UE Context Management"}),
        (r"(?i)\bUEContextReleaseCommand\b", {"message_type": "UE Context Release Command", "procedure": "UE Context Release"}),
        (r"(?i)\bUEContextReleaseRequest\b", {"message_type": "UE Context Release Request", "procedure": "UE Context Release"}),
        (r"(?i)\bUEContextReleaseComplete\b", {"message_type": "UE Context Release Complete", "procedure": "UE Context Release"}),
        (r"(?i)\bS1SetupRequest\b", {"message_type": "S1 Setup Request", "procedure": "S1 Setup"}),
        (r"(?i)\bS1SetupResponse\b", {"message_type": "S1 Setup Response", "procedure": "S1 Setup"}),
        (r"(?i)\bS1SetupFailure\b", {"message_type": "S1 Setup Failure", "procedure": "S1 Setup"}),
        (r"(?i)\bERABSetupRequest\b", {"message_type": "E-RAB Setup Request", "procedure": "E-RAB Management"}),
        (r"(?i)\bERABSetupResponse\b", {"message_type": "E-RAB Setup Response", "procedure": "E-RAB Management"}),
        (r"(?i)\bERABModifyRequest\b", {"message_type": "E-RAB Modify Request", "procedure": "E-RAB Management"}),
        (r"(?i)\bERABModifyResponse\b", {"message_type": "E-RAB Modify Response", "procedure": "E-RAB Management"}),
        (r"(?i)\bERABReleaseCommand\b", {"message_type": "E-RAB Release Command", "procedure": "E-RAB Management"}),
        (r"(?i)\bERABReleaseResponse\b", {"message_type": "E-RAB Release Response", "procedure": "E-RAB Management"}),
        (r"(?i)\bPathSwitchRequest\b", {"message_type": "Path Switch Request", "procedure": "Path Switch"}),
        (r"(?i)\bPathSwitchRequestAcknowledge\b", {"message_type": "Path Switch Request Acknowledge", "procedure": "Path Switch"}),
        (r"(?i)\bPathSwitchRequestFailure\b", {"message_type": "Path Switch Request Failure", "procedure": "Path Switch"}),
        (r"(?i)\bHandoverRequired\b", {"message_type": "Handover Required", "procedure": "Handover"}),
        (r"(?i)\bHandoverRequest\b", {"message_type": "Handover Request", "procedure": "Handover"}),
        (r"(?i)\bHandoverRequestAcknowledge\b", {"message_type": "Handover Request Acknowledge", "procedure": "Handover"}),
        (r"(?i)\bHandoverFailure\b", {"message_type": "Handover Failure", "procedure": "Handover"}),
        (r"(?i)\bHandoverCancel\b", {"message_type": "Handover Cancel", "procedure": "Handover"}),
        (r"(?i)\bHandoverCancelAcknowledge\b", {"message_type": "Handover Cancel Acknowledge", "procedure": "Handover"}),
        (r"(?i)\bHandoverNotify\b", {"message_type": "Handover Notify", "procedure": "Handover"}),
        (r"(?i)\bENBConfigurationUpdate\b", {"message_type": "ENB Configuration Update", "procedure": "Configuration Update"}),
        (r"(?i)\bENBConfigurationUpdateAcknowledge\b", {"message_type": "ENB Configuration Update Acknowledge", "procedure": "Configuration Update"}),
        (r"(?i)\bENBConfigurationUpdateFailure\b", {"message_type": "ENB Configuration Update Failure", "procedure": "Configuration Update"}),
        (r"(?i)\bMMEConfigurationUpdate\b", {"message_type": "MME Configuration Update", "procedure": "Configuration Update"}),
        (r"(?i)\bMMEConfigurationUpdateAcknowledge\b", {"message_type": "MME Configuration Update Acknowledge", "procedure": "Configuration Update"}),
        (r"(?i)\bMMEConfigurationUpdateFailure\b", {"message_type": "MME Configuration Update Failure", "procedure": "Configuration Update"}),
        (r"(?i)\bPaging\b", {"message_type": "Paging", "procedure": "Paging"}),
        (r"(?i)\bNASNonDeliveryIndication\b", {"message_type": "NAS Non Delivery Indication", "procedure": "NAS Non Delivery"}),
        (r"(?i)\bErrorIndication\b", {"message_type": "Error Indication", "procedure": "Error"}),
        (r"(?i)\bReset\b", {"message_type": "Reset", "procedure": "Reset"}),
        (r"(?i)\bResetAcknowledge\b", {"message_type": "Reset Acknowledge", "procedure": "Reset"}),
        (r"(?i)\bKillRequest\b", {"message_type": "Kill Request", "procedure": "Kill"}),
        (r"(?i)\bKillResponse\b", {"message_type": "Kill Response", "procedure": "Kill"}),
        (r"(?i)\bUEContextModificationRequest\b", {"message_type": "UE Context Modification Request", "procedure": "UE Context Management"}),
        (r"(?i)\bUEContextModificationResponse\b", {"message_type": "UE Context Modification Response", "procedure": "UE Context Management"}),
        (r"(?i)\bUEContextModificationFailure\b", {"message_type": "UE Context Modification Failure", "procedure": "UE Context Management"}),
        (r"(?i)\bUECapabilityInfoIndication\b", {"message_type": "UE Capability Info Indication", "procedure": "UE Capability"}),
        (r"(?i)\bWriteReplaceWarning\b", {"message_type": "Write-Replace Warning", "procedure": "Warning"}),
        (r"(?i)\bOverloadStart\b", {"message_type": "Overload Start", "procedure": "Overload"}),
        (r"(?i)\bOverloadStop\b", {"message_type": "Overload Stop", "procedure": "Overload"}),
        (r"(?i)\bLocationReportingControl\b", {"message_type": "Location Reporting Control", "procedure": "Location"}),
        (r"(?i)\bLocationReport\b", {"message_type": "Location Report", "procedure": "Location"}),
        (r"(?i)\bLocationReportingFailureIndication\b", {"message_type": "Location Reporting Failure Indication", "procedure": "Location"}),
        (r"(?i)\bTraceStart\b", {"message_type": "Trace Start", "procedure": "Trace"}),
        (r"(?i)\bTraceFailureIndication\b", {"message_type": "Trace Failure Indication", "procedure": "Trace"}),
        (r"(?i)\bDeactivateTrace\b", {"message_type": "Deactivate Trace", "procedure": "Trace"}),
        (r"(?i)\bCellTrafficTrace\b", {"message_type": "Cell Traffic Trace", "procedure": "Trace"}),
        (r"(?i)\bENBDirectInformationTransfer\b", {"message_type": "eNB Direct Information Transfer", "procedure": "Information Transfer"}),
        (r"(?i)\bMMEDirectInformationTransfer\b", {"message_type": "MME Direct Information Transfer", "procedure": "Information Transfer"}),
        (r"(?i)\bENBStatusTransfer\b", {"message_type": "eNB Status Transfer", "procedure": "Status Transfer"}),
        (r"(?i)\bMMEStatusTransfer\b", {"message_type": "MME Status Transfer", "procedure": "Status Transfer"}),
        (r"(?i)\bRerouteNASRequest\b", {"message_type": "Reroute NAS Request", "procedure": "Reroute NAS"}),
    ]
    
    # 匹配消息类型
    for pattern, match_data in s1ap_patterns:
        if re.search(pattern, info):
            result.update(match_data)
            break
    
    # 提取Procedure Code（S1AP ProcedureCode字段）
    proc_match = re.search(r"(?i)ProcedureCode\s*[=:]\s*(\d+)", info)
    if proc_match:
        result["procedure_code"] = proc_match.group(1)
    
    # 提取Result（成功/失败）
    if re.search(r"(?i)(success|acknowledge|complete|response)", info):
        result["result"] = "success"
    elif re.search(r"(?i)(failure|error|reject|indication)", info):
        result["result"] = "failure"
    
    return result if any(result.values()) else None


def _match_ngap_message(info: str) -> Optional[Dict]:
    """匹配NGAP消息类型"""
    info_upper = info.upper()
    
    patterns = [
        ("PDU Session Resource Setup", "PDUSessionResourceSetupResponse", 
         ["PDU Session Resource Setup Response", "PDUSessionResourceSetupResponse"]),
        ("PDU Session Resource Setup", "PDUSessionResourceSetupRequest",
         ["PDU Session Resource Setup Request", "PDUSessionResourceSetupRequest"]),
        ("Initial Context Setup", "InitialContextSetupResponse",
         ["Initial Context Setup Response", "InitialContextSetupResponse"]),
        ("Initial Context Setup", "InitialContextSetupFailure",
         ["Initial Context Setup Failure", "InitialContextSetupFailure"]),
        ("Initial Context Setup", "InitialContextSetupRequest",
         ["Initial Context Setup Request", "InitialContextSetupRequest"]),
        ("UE Context Release", "UEContextReleaseCommand",
         ["UE Context Release Command", "UEContextReleaseCommand"]),
        ("UE Context Release", "UEContextReleaseComplete",
         ["UE Context Release Complete", "UEContextReleaseComplete"]),
        ("Handover", "HandoverPreparationFailure",
         ["Handover Preparation Failure", "HandoverPreparationFailure"]),
        ("Handover", "HandoverRequired",
         ["Handover Required", "HandoverRequired"]),
        ("NAS Transport", "UplinkNASTransport",
         ["UplinkNASTransport", "Uplink NAS Transport"]),
        ("NAS Transport", "DownlinkNASTransport",
         ["DownlinkNASTransport", "Downlink NAS Transport"]),
    ]
    
    for procedure, msg_type, keywords in patterns:
        for kw in keywords:
            if kw.upper() in info_upper:
                return {"procedure": procedure, "message_type": msg_type}
    
    return None


def _match_nas5gs_message(info: str) -> Optional[Dict]:
    """匹配NAS-5GS消息类型"""
    info_lower = info.lower()
    
    patterns = [
        ("Registration", "RegistrationReject", ["registration reject"]),
        ("Registration", "RegistrationAccept", ["registration accept"]),
        ("Registration", "RegistrationRequest", ["registration request"]),
        ("Service Request", "ServiceReject", ["service reject"]),
        ("PDU Session Establishment", "PDUSessionEstablishmentReject", ["pdu session establishment reject"]),
        ("PDU Session Establishment", "PDUSessionEstablishmentAccept", ["pdu session establishment accept"]),
        ("PDU Session Establishment", "PDUSessionEstablishmentRequest", ["pdu session establishment request"]),
        ("De-registration", "DeRegistrationRequest", ["de-registration request"]),
        ("Authentication", "AuthenticationRequest", ["authentication request"]),
        ("Authentication", "AuthenticationResponse", ["authentication response"]),
        ("Authentication", "AuthenticationReject", ["authentication reject"]),
    ]
    
    for procedure, msg_type, keywords in patterns:
        for kw in keywords:
            if kw in info_lower:
                return {"procedure": procedure, "message_type": msg_type}
    
    return None


def _match_gtpv2_message(info: str) -> Optional[Dict]:
    """匹配GTPv2消息类型"""
    info_lower = info.lower()
    
    patterns = [
        ("Create Session", "CreateSessionResponse", ["create session response"]),
        ("Create Session", "CreateSessionRequest", ["create session request"]),
        ("Modify Bearer", "ModifyBearerResponse", ["modify bearer response"]),
        ("Modify Bearer", "ModifyBearerRequest", ["modify bearer request"]),
        ("Delete Session", "DeleteSessionResponse", ["delete session response"]),
        ("Delete Session", "DeleteSessionRequest", ["delete session request"]),
    ]
    
    for procedure, msg_type, keywords in patterns:
        for kw in keywords:
            if kw in info_lower:
                return {"procedure": procedure, "message_type": msg_type}
    
    return None


def _match_diameter_message(info: str) -> Optional[Dict]:
    """匹配Diameter消息类型"""
    info_lower = info.lower()
    
    if "authentication information answer" in info_lower:
        return {"procedure": "Authentication", "message_type": "AuthenticationInformationAnswer"}
    elif "authentication information request" in info_lower:
        return {"procedure": "Authentication", "message_type": "AuthenticationInformationRequest"}
    elif "update location answer" in info_lower:
        return {"procedure": "Location Management", "message_type": "UpdateLocationAnswer"}
    elif "update location request" in info_lower:
        return {"procedure": "Location Management", "message_type": "UpdateLocationRequest"}
    elif "cancel location" in info_lower:
        return {"procedure": "Location Management", "message_type": "CancelLocation"}
    
    return None


def _match_pfcp_message(info: str) -> Optional[Dict]:
    """匹配PFCP消息类型"""
    info_lower = info.lower()
    
    patterns = [
        ("Session Establishment", "PFCPSessionEstablishmentResponse", ["session establishment response"]),
        ("Session Establishment", "PFCPSessionEstablishmentRequest", ["session establishment request"]),
        ("Session Modification", "PFCPSessionModificationResponse", ["session modification response"]),
        ("Session Deletion", "PFCPSessionDeletionResponse", ["session deletion response"]),
        ("Association Setup", "PFCPAssociationSetupResponse", ["association setup response"]),
    ]
    
    for procedure, msg_type, keywords in patterns:
        for kw in keywords:
            if kw in info_lower:
                return {"procedure": procedure, "message_type": msg_type}
    
    return None


def _match_sip_message(info: str) -> Optional[Dict]:
    """匹配SIP消息类型"""
    info_upper = info.upper()
    
    if "REGISTER" in info_upper:
        if "401" in info_upper:
            return {"procedure": "Registration", "message_type": "Register401"}
        elif "403" in info_upper:
            return {"procedure": "Registration", "message_type": "Register403"}
        elif "200" in info_upper:
            return {"procedure": "Registration", "message_type": "Register200"}
        else:
            return {"procedure": "Registration", "message_type": "Register"}
    elif "INVITE" in info_upper:
        for code, name in [("404", "Invite404"), ("480", "Invite480"),
                          ("486", "Invite486"), ("403", "Invite403"),
                          ("200", "Invite200")]:
            if code in info_upper:
                return {"procedure": "Call", "message_type": name}
        return {"procedure": "Call", "message_type": "Invite"}
    
    return None