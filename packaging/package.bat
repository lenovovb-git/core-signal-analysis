@echo off
chcp 65001 >nul
REM ============================================================
REM  核心网信令分析Agent - Windows 一键打包脚本
REM  前提：已安装 Python 3.10+（安装时务必勾选 "Add Python to PATH"）
REM  用法：在项目根目录双击本文件即可
REM ============================================================
cd /d %~dp0\..

echo [1/4] 升级 pip 并安装打包工具 PyInstaller...
python -m pip install --upgrade pip
pip install pyinstaller

echo [2/4] 安装项目依赖...
pip install .

echo [3/4] 开始打包（首次约需几分钟，请耐心等待）...
pyinstaller packaging\core_signal_agent.spec --noconfirm

echo.
echo [4/4] 打包完成！生成的程序在：dist\CoreSignalAgent.exe
echo 首次使用前：在 dist\CoreSignalAgent.exe 旁边放一个 .env，填入你的 LLM_API_KEY
echo 并确保已安装 Wireshark（tshark 一般会自动探测，无需手动配置）
pause
