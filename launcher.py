"""
打包后的启动器：双击 exe 时启动 Streamlit 网页界面并自动打开浏览器。
开发模式下也能直接运行：python launcher.py
"""
import os
import sys
import webbrowser
import threading
import time


def _detect_tshark():
    """Windows 上自动探测 Wireshark 自带的 tshark 路径（无需手动配置）"""
    candidates = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def _user_data_dir():
    """案例数据库放到用户"文档"目录，保证重启后不丢失"""
    d = os.path.join(os.path.expanduser("~"), "Documents", "core-signal-agent", "data")
    os.makedirs(d, exist_ok=True)
    return d


def main():
    # 1) 案例数据库：落在用户文档目录（可写、持久保存）
    os.environ["CASE_DB_PATH"] = os.path.join(_user_data_dir(), "cases.sqlite")

    # 2) 自动探测 tshark（仅当 .env 没配 TSHARK_PATH 时生效）
    if not os.environ.get("TSHARK_PATH"):
        detected = _detect_tshark()
        if detected:
            os.environ["TSHARK_PATH"] = detected

    # 3) 找到网页界面脚本（开发时在 ./ui，打包后在 _MEIPASS/ui）
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.path.dirname(os.path.abspath(__file__))
    app_script = os.path.join(base, "ui", "streamlit_app.py")
    if not os.path.exists(app_script):
        app_script = os.path.join(getattr(sys, "_MEIPASS", base), "ui", "streamlit_app.py")

    # 4) 启动后自动打开浏览器
    def _open_browser():
        time.sleep(2.5)
        webbrowser.open("http://localhost:8501")

    threading.Thread(target=_open_browser, daemon=True).start()

    # 5) 启动 Streamlit
    import streamlit.web.cli as cli

    sys.argv = [
        "streamlit", "run", app_script,
        "--server.headless", "false",
        "--browser.gatherUsageStats", "false",
    ]
    cli.main()


if __name__ == "__main__":
    main()
