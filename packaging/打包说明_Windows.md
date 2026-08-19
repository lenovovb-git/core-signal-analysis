# 在 Windows 上打包成「双击就能运行」的 exe

本说明面向**不懂代码**的使用者。跟着做，就能得到一个 `CoreSignalAgent.exe`，双击它就会自动打开浏览器使用。

---

## 一、你需要先准备的 3 样东西

1. **一台 Windows 电脑**（Win10 / Win11 均可）。
2. **Python 3.10 或更高版本**
   - 下载：https://www.python.org/downloads/windows/
   - 安装时**第一屏务必勾选 "Add Python to PATH"**（这步最关键，忘了后面会失败）。
3. **Wireshark**（程序依赖它自带的 `tshark` 来读抓包文件）
   - 下载：https://www.wireshark.org/download.html
   - 安装时保持默认勾选 `tshark` 即可（一般默认就带）。

> 说明：Python 和 Wireshark 只需装一次。打好的 exe 本身已经把项目代码打包进去了，但 **tshark 和你的 API Key 没法塞进 exe**，所以用的人仍要装 Wireshark、并在 exe 旁边放一个 `.env` 写密钥。

---

## 二、打包步骤（只用做一次）

1. 把整个项目弄到 Windows 上：
   - 方式 A：去 GitHub 仓库点 `Code → Download ZIP`，解压。
   - 方式 B（若会 git）：`git clone https://github.com/lenovovb-git/core-signal-analysis.git`。
2. 进入项目根目录，找到 `packaging\package.bat`，**双击它**。
3. 会弹出黑色窗口自动执行，耐心等几分钟，最后出现：
   `dist\CoreSignalAgent.exe` 即代表成功。

> 如果黑窗口报红字，把红字截图发我，我帮你判断。

---

## 三、首次使用前的一次性配置

1. 打开 `dist` 文件夹，在 `CoreSignalAgent.exe` **同一个目录**里新建一个文件，命名为 `.env`
   （注意前面有个点；如果 Windows 不让你以点开头命名，可以先存成 `env.txt` 再改名）。
2. 用记事本打开 `.env`，填入以下内容并保存：

```
LLM_API_KEY=这里填你的真实APIKey
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

- `LLM_API_KEY` **必填**，没有它无法生成分析报告。
- `TSHARK_PATH` 一般**不用写**（程序会自动去 Wireshark 默认安装目录找）；只有你装 Wireshark 时改了路径才需要手动写，例如：
  `TSHARK_PATH=D:\tools\Wireshark\tshark.exe`

---

## 四、日常使用

双击 `CoreSignalAgent.exe`：

- 会弹出一个黑色命令行窗口（**正常现象，不要关，关了程序就退出**）；
- 同时自动打开浏览器，跳到 `http://localhost:8501`；
- 在网页里上传 `.pcap` / `.pcapng` 抓包文件，填目标帧号，点「开始分析」即可。

---

## 五、常见问题

| 现象 | 原因 / 解决 |
|---|---|
| 黑窗口一闪而过 / 报 `tshark 未找到` | 没装 Wireshark，或装到了非默认路径。装好 Wireshark 即可（默认路径会自动识别）。 |
| 网页打不开 / 报 API 错误 | `.env` 里 `LLM_API_KEY` 没填或填错。检查 `.env` 是否在 exe 同目录。 |
| exe 体积好几百 MB | 正常。Streamlit 打包本来就大，不影响使用。 |
| 端口 8501 被占用 | 关掉占用 8501 的程序，或改 `launcher.py` 里的端口后重新打包。 |
| 案例保存后找不到了 | 案例数据库存在 `文档\core-signal-agent\data\cases.sqlite`，不是 exe 旁边。 |

---

## 六、技术备注（给想了解的人）

- 入口是 `launcher.py`：双击后启动 Streamlit 本地服务并自动开浏览器。
- 打包配置 `packaging/core_signal_agent.spec` 已用 `collect_all("streamlit")` 收集 Streamlit 的全部隐藏依赖，避免打包后缺模块。
- 案例数据写到用户「文档」目录，保证 exe 重启后数据不丢。
- 在 macOS / Linux 上**无法**打出 Windows 的 exe，必须在本机 Windows 或 GitHub Actions（Windows 环境）中打包。
