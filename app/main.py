"""
CLI入口 - 命令行分析工具
"""
import argparse
import logging
import sys
from pathlib import Path

from .config import ensure_directories
from .agent import CoreSignalAgent


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


def analyze_command(args):
    """执行分析命令"""
    ensure_directories()
    
    agent = CoreSignalAgent(
        rules_dir=args.rules_dir,
        case_db_path=args.case_db,
        use_llm=not args.no_llm
    )
    
    try:
        result = agent.analyze(
            pcap_path=args.pcap,
            frame_number=args.frame,
            window=args.window,
            match_mode=args.match_mode
        )
        
        # 输出结果
        print("=" * 60)
        print("核心网信令分析报告")
        print("=" * 60)
        
        summary = result.get("summary", {})
        print(f"\n协议: {summary.get('protocol', 'N/A')}")
        print(f"消息类型: {summary.get('message_type', 'N/A')}")
        print(f"Cause: {summary.get('cause', 'N/A')}")
        print(f"匹配规则: {summary.get('matched_rules_count', 0)}条")
        print(f"相似案例: {summary.get('similar_cases_count', 0)}个")
        print(f"报告类型: {summary.get('report_type', 'N/A')}")
        
        print("\n" + "-" * 60)
        report = result.get("analysis_report", {})
        content = report.get("content", "无报告内容")
        print(content)
        print("-" * 60)
        
        # 保存报告到文件
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
            logger.info(f"报告已保存到: {output_path}")
        
        agent.close()
        
    except Exception as e:
        logger.error(f"分析失败: {e}")
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


def test_command(args):
    """测试tshark可用性"""
    from .packet_parser import test_tshark_available
    
    print("测试tshark可用性...")
    if test_tshark_available():
        print("✓ tshark 可用")
    else:
        print("✗ tshark 不可用，请安装Wireshark并确保tshark在PATH中")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="核心网信令分析Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 分析指定帧
  python -m app.main analyze capture.pcapng --frame 1532
  
  # 使用LLM生成详细报告
  python -m app.main analyze capture.pcap --frame 100 --llm
  
  # 测试tshark
  python -m app.main test
  
  # 启动Web界面
  streamlit run ui/streamlit_app.py
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # analyze子命令
    analyze_parser = subparsers.add_parser("analyze", help="分析抓包文件")
    analyze_parser.add_argument("pcap", help="pcap/pcapng文件路径")
    analyze_parser.add_argument("--frame", "-f", type=int, required=True, help="目标帧号")
    analyze_parser.add_argument("--window", "-w", type=int, default=20, help="上下文窗口大小")
    analyze_parser.add_argument("--match-mode", "-m", choices=["exact", "fuzzy"], default="exact", help="规则匹配模式")
    analyze_parser.add_argument("--no-llm", action="store_true", help="不使用LLM，仅使用规则库")
    analyze_parser.add_argument("--llm", dest="no_llm", action="store_false", help="使用LLM")
    analyze_parser.add_argument("--rules-dir", help="规则目录路径")
    analyze_parser.add_argument("--case-db", help="案例数据库路径")
    analyze_parser.add_argument("--output", "-o", help="报告输出文件路径")
    
    # test子命令
    test_parser = subparsers.add_parser("test", help="测试环境")
    
    args = parser.parse_args()
    
    if args.command == "analyze":
        analyze_command(args)
    elif args.command == "test":
        test_command(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()