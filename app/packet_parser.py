"""
抓包解析模块 - 使用tshark解析pcap文件
"""
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

from .config import settings


logger = logging.getLogger(__name__)


def run_tshark(command: List[str]) -> str:
    """执行tshark命令"""
    try:
        result = subprocess.run(
            [settings.tshark_path] + command,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"tshark命令执行失败: {e.stderr}")
        raise RuntimeError(f"tshark解析失败: {e.stderr}")
    except FileNotFoundError:
        logger.error(f"tshark未找到，请检查路径: {settings.tshark_path}")
        raise RuntimeError(f"tshark未找到，请安装Wireshark或检查配置")


def parse_packet(pcap_path: str, frame_number: int) -> Dict[str, Any]:
    """
    解析指定帧的报文
    
    Args:
        pcap_path: pcap文件路径
        frame_number: 帧号
        
    Returns:
        报文解析结果
    """
    pcap_path = Path(pcap_path).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap文件不存在: {pcap_path}")
    
    # 使用tshark解析指定帧（输出完整协议树）
    command = [
        "-r", str(pcap_path),
        "-Y", f"frame.number == {frame_number}",
        "-T", "json"
    ]
    
    try:
        output = run_tshark(command)
        data = json.loads(output)
        
        if not data:
            raise ValueError(f"未找到帧号 {frame_number} 的报文")
        
        packet = data[0]  # 第一层是列表
        layers = packet.get("_source", {}).get("layers", {})
        frame_layer = layers.get("frame", {})
        
        # 单独提取列信息（tshark -T json 模式下 _ws.col 不会出现在协议树中）
        info, protocols_str = "", ""
        try:
            col_command = [
                "-r", str(pcap_path),
                "-Y", f"frame.number == {frame_number}",
                "-T", "fields",
                "-e", "_ws.col.Info",
                "-e", "_ws.col.Protocol"
            ]
            col_output = run_tshark(col_command).strip()
            if col_output:
                parts = col_output.split("\t")
                info = parts[0] if len(parts) > 0 else ""
                protocols_str = parts[1] if len(parts) > 1 else ""
        except Exception:
            logger.debug("无法提取列信息，回退到帧层数据")
        
        return {
            "frame_number": frame_number,
            "timestamp": frame_layer.get("frame.time", ""),
            "protocols": extract_protocols(layers),
            "info": info,
            "protocols_str": protocols_str,
            "raw_layers": layers,
            "raw_packet": packet
        }
    except json.JSONDecodeError as e:
        logger.error(f"JSON解析失败: {e}")
        raise RuntimeError(f"tshark输出格式异常: {e}")


def parse_context(pcap_path: str, frame_number: int, window: int = None) -> List[Dict[str, Any]]:
    """
    解析指定帧的上下文报文
    
    Args:
        pcap_path: pcap文件路径
        frame_number: 中心帧号
        window: 上下文窗口大小，默认使用配置
        
    Returns:
        上下文报文列表
    """
    if window is None:
        window = settings.default_window
    
    pcap_path = Path(pcap_path).resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap文件不存在: {pcap_path}")
    
    # 计算帧号范围
    start_frame = max(1, frame_number - window // 2)
    end_frame = frame_number + window // 2
    
    # 使用tshark解析范围内的报文（简化版，只提取基本信息）
    command = [
        "-r", str(pcap_path),
        "-Y", f"frame.number >= {start_frame} and frame.number <= {end_frame}",
        "-T", "json",
        "-e", "frame.number",
        "-e", "frame.time",
        "-e", "_ws.col.Protocol",
        "-e", "_ws.col.Info"
    ]
    
    try:
        output = run_tshark(command)
        data = json.loads(output)
        
        context_packets = []
        for packet in data:
            layers = packet.get("_source", {}).get("layers", {})
            frame_num = int(layers.get("frame", {}).get("frame.number", "0"))
            
            context_packets.append({
                "frame_number": frame_num,
                "timestamp": layers.get("frame", {}).get("frame.time", ""),
                "protocols": extract_protocols(layers),
                "info": layers.get("frame", {}).get("_ws.col.Info", ""),
                "is_target": frame_num == frame_number
            })
        
        # 按帧号排序
        context_packets.sort(key=lambda x: x["frame_number"])
        return context_packets
    except json.JSONDecodeError as e:
        logger.error(f"JSON解析失败: {e}")
        raise RuntimeError(f"tshark输出格式异常: {e}")


def extract_protocols(layers: Dict[str, Any]) -> List[str]:
    """从layers中提取协议栈"""
    protocols = []
    
    # frame层总是存在
    if "frame" in layers:
        protocols.append("frame")
    
    # 其他协议层
    for key in layers:
        if key != "frame" and not key.startswith("_"):
            protocols.append(key)
    
    return protocols


def extract_fields(raw_packet: Dict[str, Any]) -> Dict[str, Any]:
    """
    从原始报文中提取关键字段
    
    Args:
        raw_packet: tshark原始输出
        
    Returns:
        关键字段字典
    """
    layers = raw_packet.get("_source", {}).get("layers", {})
    
    # 这里实现具体的字段提取逻辑
    # 后续会由normalizer模块实现
    return {
        "raw_layers": layers,
        "protocol_stack": extract_protocols(layers),
        "info": layers.get("frame", {}).get("_ws.col.Info", "")
    }


def test_tshark_available() -> bool:
    """测试tshark是否可用"""
    try:
        result = subprocess.run(
            [settings.tshark_path, "--version"],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"tshark版本: {result.stdout.splitlines()[0]}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False