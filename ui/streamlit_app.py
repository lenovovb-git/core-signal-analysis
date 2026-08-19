"""
Streamlit Web界面 - 核心网信令分析Agent
"""
import streamlit as st
import tempfile
import os
from pathlib import Path
import json

from app.config import ensure_directories, settings
from app.agent import CoreSignalAgent


# 页面配置
st.set_page_config(
    page_title="核心网信令分析Agent",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 初始化
ensure_directories()


def init_session_state():
    """初始化会话状态"""
    if "analysis_result" not in st.session_state:
        st.session_state.analysis_result = None
    if "agent" not in st.session_state:
        st.session_state.agent = None
    if "uploaded_file" not in st.session_state:
        st.session_state.uploaded_file = None
    if "temp_file_path" not in st.session_state:
        st.session_state.temp_file_path = None


def create_agent():
    """创建Agent实例"""
    if st.session_state.agent is None:
        use_llm = st.session_state.get("use_llm", True)
        st.session_state.agent = CoreSignalAgent(use_llm=use_llm)


def cleanup_temp_file():
    """清理临时文件"""
    if (st.session_state.temp_file_path and 
        os.path.exists(st.session_state.temp_file_path)):
        try:
            os.unlink(st.session_state.temp_file_path)
            st.session_state.temp_file_path = None
        except:
            pass


def save_uploaded_file(uploaded_file):
    """保存上传的文件到临时目录"""
    cleanup_temp_file()
    
    with tempfile.NamedTemporaryFile(
        delete=False, 
        suffix=Path(uploaded_file.name).suffix
    ) as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        st.session_state.temp_file_path = tmp_file.name
    
    return st.session_state.temp_file_path


def display_analysis_result(result):
    """显示分析结果"""
    if not result:
        return
    
    st.subheader("📊 分析结果")
    
    # 摘要信息
    summary = result.get("summary", {})
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("协议", summary.get("protocol", "N/A"))
    with col2:
        st.metric("消息类型", summary.get("message_type", "N/A"))
    with col3:
        st.metric("匹配规则", summary.get("matched_rules_count", 0))
    with col4:
        st.metric("相似案例", summary.get("similar_cases_count", 0))
    
    # 详细报告
    report = result.get("analysis_report", {})
    
    if report.get("is_error"):
        st.error("报告生成失败")
        st.code(report.get("content", "无错误信息"), language="text")
    else:
        st.markdown("### 📝 详细分析报告")
        st.markdown(report.get("content", "无报告内容"))
    
    # 上下文信息
    with st.expander("🔍 查看上下文信息"):
        context = result.get("context", {})
        
        tab1, tab2, tab3, tab4 = st.tabs([
            "目标报文", "相关报文", "匹配规则", "相似案例"
        ])
        
        with tab1:
            selected = context.get("selected_packet", {})
            st.json(selected, expanded=False)
        
        with tab2:
            related = context.get("related_packets", [])
            if related:
                for pkt in related[:10]:
                    prefix = "🎯 " if pkt.get("is_target") else "   "
                    st.text(f"{prefix}{pkt.get('frame_number')}: {pkt.get('protocols', [])} - {pkt.get('info', '')}")
            else:
                st.info("无相关报文")
        
        with tab3:
            rules = context.get("matched_rules", [])
            if rules:
                for rule in rules[:5]:
                    with st.expander(f"📋 {rule.get('title', '未命名规则')} (匹配度: {rule.get('score', 0):.2f})"):
                        st.write("**可能原因:**")
                        for cause in rule.get("possible_causes", [])[:3]:
                            st.write(f"- {cause.get('title', '')}")
            else:
                st.info("未匹配到专家规则")
        
        with tab4:
            cases = context.get("similar_cases", [])
            if cases:
                for case in cases[:3]:
                    with st.expander(f"📚 {case.get('title', '未命名案例')}"):
                        st.write(f"**根因:** {case.get('root_cause', 'N/A')}")
                        st.write(f"**解决方案:** {case.get('solution', 'N/A')}")
            else:
                st.info("未找到相似历史案例")
    
    # 保存选项
    st.markdown("---")
    st.subheader("💾 保存结果")
    
    col1, col2 = st.columns(2)
    
    with col1:
        with st.form("save_case_form"):
            st.write("**保存为历史案例**")
            case_title = st.text_input("案例标题", value=f"{summary.get('protocol', '')} {summary.get('message_type', '')} 分析")
            root_cause = st.text_area("根因分析", height=100)
            solution = st.text_area("解决方案", height=100)
            
            if st.form_submit_button("💾 保存案例"):
                if st.session_state.agent and root_cause and solution:
                    try:
                        case_id = st.session_state.agent.save_as_case(
                            result, case_title, root_cause, solution
                        )
                        st.success(f"案例已保存，ID: {case_id}")
                    except Exception as e:
                        st.error(f"保存失败: {e}")
    
    with col2:
        with st.form("save_rule_form"):
            st.write("**生成规则草稿**")
            rule_title = st.text_input("规则标题", value=f"{summary.get('protocol', '')} {summary.get('message_type', '')} 规则")
            
            if st.form_submit_button("📝 生成规则草稿"):
                if st.session_state.agent:
                    try:
                        rule_draft = st.session_state.agent.generate_rule_draft(
                            result, rule_title, []
                        )
                        st.session_state.rule_draft = rule_draft
                        st.success("规则草稿已生成")
                        
                        with st.expander("查看规则草稿"):
                            st.json(rule_draft, expanded=True)
                    except Exception as e:
                        st.error(f"生成失败: {e}")


def main():
    """主界面"""
    init_session_state()
    
    st.title("📡 核心网信令分析Agent")
    st.markdown("""
    这是一个本地运行的核心网信令分析工具，支持分析4G/5G/IMS信令失败原因。
    
    使用步骤：
    1. 上传抓包文件 (.pcap/.pcapng)
    2. 输入目标帧号 (Wireshark中的frame.number)
    3. 点击"开始分析"
    4. 查看分析报告和保存结果
    """)
    
    # 侧边栏配置
    with st.sidebar:
        st.header("⚙️ 配置")
        
        use_llm = st.checkbox(
            "使用LLM分析", 
            value=True,
            help="使用大模型生成详细分析报告，需要配置LLM API"
        )
        st.session_state.use_llm = use_llm
        
        match_mode = st.selectbox(
            "规则匹配模式",
            ["exact", "fuzzy"],
            index=0,
            help="exact: 精确匹配, fuzzy: 模糊匹配"
        )
        
        window_size = st.slider(
            "上下文窗口大小",
            min_value=5,
            max_value=50,
            value=20,
            help="分析目标报文前后的报文数量"
        )
        
        st.markdown("---")
        st.header("📊 统计信息")
        
        if st.session_state.agent:
            try:
                case_count = st.session_state.agent.case_store.count_cases()
                st.metric("历史案例数", case_count)
            except:
                st.metric("历史案例数", 0)
        
        st.markdown("---")
        st.info("""
        **使用提示：**
        - 确保已安装Wireshark
        - 大文件分析可能需要较长时间
        - 敏感数据默认本地处理
        - 可保存分析结果为案例供后续参考
        """)
    
    # 主界面
    st.header("📁 上传抓包文件")
    
    uploaded_file = st.file_uploader(
        "选择pcap/pcapng文件",
        type=["pcap", "pcapng"],
        help="支持Wireshark抓包文件格式"
    )
    
    if uploaded_file:
        st.session_state.uploaded_file = uploaded_file
        file_path = save_uploaded_file(uploaded_file)
        
        st.success(f"文件已上传: {uploaded_file.name}")
        st.info(f"临时文件路径: {file_path}")
    
    st.header("🔍 分析设置")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if st.session_state.uploaded_file:
            frame_number = st.number_input(
                "目标帧号 (frame.number)",
                min_value=1,
                value=1,
                help="在Wireshark中查看的帧号"
            )
        else:
            frame_number = st.number_input(
                "目标帧号 (frame.number)",
                min_value=1,
                value=1,
                disabled=True,
                help="请先上传文件"
            )
    
    with col2:
        st.write("")
        st.write("")
        analyze_button = st.button(
            "🚀 开始分析",
            type="primary",
            disabled=not st.session_state.uploaded_file,
            use_container_width=True
        )
    
    # 执行分析
    if analyze_button and st.session_state.uploaded_file:
        create_agent()
        
        with st.spinner("正在分析..."):
            try:
                result = st.session_state.agent.analyze(
                    pcap_path=st.session_state.temp_file_path,
                    frame_number=frame_number,
                    window=window_size,
                    match_mode=match_mode
                )
                st.session_state.analysis_result = result
                st.rerun()
            except Exception as e:
                st.error(f"分析失败: {e}")
    
    # 显示结果
    if st.session_state.analysis_result:
        display_analysis_result(st.session_state.analysis_result)
    
    # 页脚
    st.markdown("---")
    st.caption("核心网信令分析Agent v0.1.0 | 本地运行，数据安全")


if __name__ == "__main__":
    main()