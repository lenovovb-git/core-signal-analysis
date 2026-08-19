# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：将网页界面版打包为 Windows 单文件 exe"""
from PyInstaller.utils.hooks import collect_all

# 收集 streamlit 及其全部数据文件 / 隐藏依赖（streamlit 打包必须）
datas_streamlit, binaries_streamlit, hiddenimports_streamlit = collect_all("streamlit")

# 项目自身的包与资源
proj_datas = [
    ("ui/streamlit_app.py", "ui"),
    ("app", "app"),
    ("knowledge", "knowledge"),
]
proj_hidden = [
    "app", "app.config", "app.agent", "app.case_store",
    "app.llm_client", "app.main", "app.normalizer",
    "app.packet_parser", "app.rule_engine",
    "yaml", "dotenv",
]

a = Analysis(
    ["launcher.py"],
    pathex=["."],
    binaries=binaries_streamlit,
    datas=proj_datas + datas_streamlit,
    hiddenimports=proj_hidden + hiddenimports_streamlit,
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="CoreSignalAgent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,   # 保留黑色命令行窗口便于查看报错；稳定后可改为 False 隐藏
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
