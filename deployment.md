# 核心网信令分析 Agent - 部署与操作使用文档

## 1. 项目简介

核心网信令分析 Agent（core-signal-agent）是一个**本地运行**的核心网信令智能分析工具，面向通信网络运维和排障场景。

### 核心能力

- **多协议支持**：NGAP、S1AP、NAS-5GS、NAS-EPS、Diameter、GTPv2-C、PFCP、SIP 等
- **专家规则引擎**：内置 10 条初始规则（NGAP 5条 + NAS-5GS 5条），支持 YAML 自定义扩展
- **历史案例匹配**：基于 SQLite 的案例存储与相似度检索
- **LLM 智能分析**：接入大模型生成结构化排障报告（可选，不配置也不影响使用）
- **本地运行**：所有数据在本地处理，抓包不上传云端，敏感字段自动脱敏

### 适用场景

- 4G/5G/IMS 信令失败根因分析
- 协议流程异常排查
- 专家经验沉淀与知识迭代

---

## 2. 环境要求

### 2.1 Python 版本

| 项目 | 最低要求 |
|------|----------|
| Python | **3.10+** |

推荐 Python 3.11 或更高版本。

### 2.2 操作系统

| 系统 | 支持情况 |
|------|----------|
| macOS | 完全支持（主要开发环境） |
| Linux | 完全支持 |
| Windows | 支持（需配置 tshark 路径） |

### 2.3 Wireshark / tshark

> **必需依赖**。tshark 是 Wireshark 的命令行工具，用于解析 pcap/pcapng 抓包文件。

**安装方式**：

| 系统 | 安装命令 |
|------|----------|
| macOS | `brew install wireshark`（默认路径 `/usr/local/bin/tshark`） |
| Ubuntu/Debian | `sudo apt install tshark`（默认路径 `/usr/bin/tshark`） |
| Windows | 下载 [Wireshark](https://www.wireshark.org/download.html)，安装时勾选"TShark"组件 |

**验证安装**：

```bash
tshark --version
```

### 2.4 LLM API（可选）

不配置 LLM 时，Agent 仍可基于规则库和历史案例生成分析报告，但报告较为精简。如需详细分析，需准备 OpenAI 兼容接口的 API Key。

支持的 API 提供商：

- OpenAI 官方
- 任意 OpenAI 兼容接口（Azure、DeepSeek、通义千问等）
- Ollama 本地模型（通过 `LLM_BASE_URL=http://localhost:11434/v1` 接入）

---

## 3. 部署步骤

### 3.1 克隆/解压项目

```bash
# 如果使用 git 克隆
git clone <repository-url>
cd core-signal-agent

# 如果通过 zip 包部署
unzip core-signal-agent.zip
cd core-signal-agent
```

### 3.2 安装 Python 依赖

```bash
pip install -e .
```

核心依赖包：

| 包名 | 版本要求 | 用途 |
|------|----------|------|
| streamlit | >=1.28.0 | Web UI 界面 |
| pyyaml | >=6.0 | 专家规则文件解析 |
| httpx | >=0.25.0 | LLM API 调用 |
| pydantic | >=2.0.0 | 数据验证 |
| pydantic-settings | >=2.0.0 | 配置管理 |
| python-dotenv | >=1.0.0 | .env 环境配置加载 |

### 3.3 配置环境变量

```bash
cp .env.example .env
```

编辑 `.env` 文件，关键配置项：

```bash
# ========== LLM 配置（可选） ==========
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=sk-your-api-key-here

# ========== 本地配置 ==========
# macOS 默认路径，Linux 通常为 /usr/bin/tshark
TSHARK_PATH=/usr/local/bin/tshark
# Windows 示例：C:\Program Files\Wireshark\tshark.exe

# 上下文窗口大小（目标帧前后各取多少帧）
DEFAULT_WINDOW=20

# 案例数据库路径（相对于项目根目录）
CASE_DB_PATH=data/cases.sqlite
```

> **Windows 用户注意**：tshark 路径需使用双反斜杠，如 `TSHARK_PATH=C:\\Program Files\\Wireshark\\tshark.exe`。

### 3.4 验证部署

```bash
# 测试 tshark 可用性
python -m app.main test
```

预期输出：

```
测试tshark可用性...
✓ tshark 可用
```

---

## 4. 使用方式

### 4.1 CLI 命令行方式

CLI 入口为 `app/main.py`，通过 `python -m app.main` 调用。

#### 测试环境

```bash
python -m app.main test
```

#### 分析抓包文件（基础模式，不使用 LLM）

```bash
python -m app.main analyze <pcap文件路径> --frame <帧号>
```

示例：

```bash
# 分析 test.pcap 的第 1532 帧
python -m app.main analyze samples/test.pcap --frame 1532

# 指定上下文窗口大小
python -m app.main analyze capture.pcapng --frame 100 --window 30

# 使用模糊规则匹配模式
python -m app.main analyze capture.pcap --frame 50 --match-mode fuzzy
```

#### 分析抓包文件（LLM 模式）

```bash
python -m app.main analyze capture.pcapng --frame 1532 --llm
```

#### 导出报告到文件

```bash
python -m app.main analyze capture.pcapng --frame 1532 --llm -o report.md
```

#### CLI 完整参数

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `pcap` | — | pcap/pcapng 文件路径 | 必填 |
| `--frame` | `-f` | 目标帧号 | 必填 |
| `--window` | `-w` | 上下文窗口大小 | 20 |
| `--match-mode` | `-m` | 规则匹配模式（exact / fuzzy） | exact |
| `--no-llm` | — | 不使用 LLM | — |
| `--llm` | — | 使用 LLM | — |
| `--rules-dir` | — | 自定义规则目录 | knowledge/rules |
| `--case-db` | — | 自定义案例数据库路径 | data/cases.sqlite |
| `--output` | `-o` | 报告输出文件路径 | — |

### 4.2 Streamlit Web 界面

#### 启动

```bash
streamlit run ui/streamlit_app.py
```

启动后在浏览器打开 `http://localhost:8501`。

#### 操作流程

1. **上传抓包文件**：点击"选择 pcap/pcapng 文件"，从本地选取抓包文件
2. **输入目标帧号**：在 Wireshark 中找到异常消息的 `frame.number`，填入
3. **配置选项**（侧边栏）：
   - 开启/关闭 LLM 分析
   - 选择规则匹配模式（精确 / 模糊）
   - 调整上下文窗口大小
4. **开始分析**：点击"开始分析"按钮
5. **查看结果**：
   - 摘要指标卡片（协议、消息类型、匹配规则数、相似案例数）
   - 详细分析报告（Markdown 格式）
   - 上下文信息（目标报文、相关报文、匹配规则、相似案例）
6. **保存结果**：
   - 保存为历史案例：需填写标题、根因分析、解决方案
   - 生成规则草稿：将本次分析结论提炼为新规则草稿

---

## 5. S1AP 协议支持说明

### 5.1 支持范围

项目从 v0.1.0 起**完整支持 S1AP（S1 Application Protocol）**协议的分析，覆盖 4G/LTE E-UTRAN 接入网场景。

### 5.2 S1AP 流程映射

项目 `app/normalizer.py` 内置了以下 S1AP 流程的识别规则：

| S1AP 流程 | 支持的消息类型 |
|-----------|---------------|
| Initial UE Message | InitialUEMessage |
| Downlink/Uplink NAS Transport | DownlinkNASTransport, UplinkNASTransport |
| Initial Context Setup | Request / Response / Failure |
| UE Context Release | Command / Complete |
| UE Context Modification | Request / Response / Failure |
| E-RAB Setup / Modify / Release | Request / Response |
| Handover | Required / Request / Request Acknowledge / Failure / Cancel / Notify |
| Path Switch | Request / Request Acknowledge / Failure |
| S1 Setup | Request / Response / Failure |
| Paging | Paging |
| Reset | Reset / Reset Acknowledge |
| Error Indication | ErrorIndication |
| Overload Control | Overload Start / Overload Stop |
| Trace | Trace Start / Failure Indication / Deactivate Trace |
| Location Reporting | Reporting Control / Report / Failure Indication |
| eNB/MME Configuration Update | Update / Acknowledge / Failure |
| eNB/MME Direct Information Transfer | Direct Information Transfer |
| eNB/MME Status Transfer | Status Transfer |

### 5.3 Cause 值提取

S1AP 的 Cause 值从 `s1ap.CauseGroup` 和 `s1ap.CauseValue` 字段提取，支持 `radioNetwork`、`transport`、`nas`、`protocol`、`misc` 五大 Cause 组。

### 5.4 注意事项

- S1AP 分析依赖 tshark 解析输出中的 Info 字段（`_ws.col.Info`），请确保 tshark 版本支持 S1AP 协议解析（Wireshark 3.0+ 均支持）
- 如果 Info 字段中未包含可识别的消息类型名（如自定义的 S1AP 消息），可通过注册新规则来覆盖
- S1AP 的专家规则建议编写在 `knowledge/rules/s1ap.yaml` 中（参考已有 NAS-5GS/NGAP 规则格式）

---

## 6. 常见问题排查

### Q1：tshark 找不到

**现象**：`RuntimeError: tshark未找到，请安装Wireshark或检查配置`

**排查**：

```bash
# 检查 tshark 是否安装
which tshark

# macOS 常见位置
ls /usr/local/bin/tshark
ls /opt/homebrew/bin/tshark

# Linux 常见位置
ls /usr/bin/tshark

# Windows 常见位置
# dir "C:\Program Files\Wireshark\tshark.exe"
```

找到实际路径后修改 `.env` 中的 `TSHARK_PATH`。

### Q2：pip install -e . 安装失败

**原因**：Python 版本低于 3.10，或 setuptools 版本过旧。

**解决**：

```bash
# 确认 Python 版本
python --version

# 升级 setuptools
pip install --upgrade setuptools wheel

# 重新安装
pip install -e .
```

### Q3：Streamlit 启动后页面空白 / 端口冲突

**解决**：

```bash
# 指定端口启动
streamlit run ui/streamlit_app.py --server.port 8502

# 查看详细日志
streamlit run ui/streamlit_app.py --logger.level debug
```

### Q4：分析报告内容不完整 / 无规则匹配

**可能原因**：

1. 抓包文件中没有目标协议（确认 pcap 包含 NGAP/S1AP/NAS 等信令）
2. 帧号输入错误（请从 Wireshark 中确认正确的 `frame.number`）
3. 规则库中暂无匹配该场景的规则

**解决**：

- 使用 `--match-mode fuzzy` 扩大匹配范围
- 在 `knowledge/rules/` 目录添加对应的 YAML 规则文件
- 配置 LLM 接口以获得更详细的分析

### Q5：LLM API 调用失败

**现象**：报告使用"规则库模式"而不是 LLM 生成的详细报告。

**检查**：

```bash
# 确认 .env 中配置了有效的 API_KEY
cat .env | grep LLM_API_KEY

# 确认 API 接口连通性
curl -H "Authorization: Bearer your-api-key" https://api.openai.com/v1/models
```

常见错误码：

| 状态码 | 原因 | 解决 |
|--------|------|------|
| 401 | API Key 无效 | 检查 `.env` 中的 `LLM_API_KEY` |
| 404 | 模型名错误 | 检查 `LLM_MODEL` 是否与 API 兼容 |
| 超时 | 网络不通 | 检查 `LLM_BASE_URL` 是否可访问 |
| 429 | 速率限制 | 等待后重试，或降低调用频率 |

### Q6：项目目录结构不完整

部署后确保以下目录结构存在：

```
core-signal-agent/
├── app/                    # 核心模块（必须）
├── ui/
│   └── streamlit_app.py    # Web UI（必须）
├── knowledge/
│   ├── rules/              # 专家规则（必须）
│   └── protocol_fields/    # 协议字段说明（必须）
├── data/                   # 案例数据库（自动创建）
├── .env                    # 环境配置（必须）
└── pyproject.toml          # 项目配置（必须）
```

`data/` 目录会在首次运行时自动创建，无需手动新建。

---

## 7. 项目结构参考

```
core-signal-agent/
├── app/                    # 核心模块
│   ├── __init__.py
│   ├── main.py             # CLI 入口
│   ├── config.py           # 配置管理（pydantic-settings）
│   ├── packet_parser.py    # tshark 抓包解析
│   ├── normalizer.py       # 信令标准化（协议/流程/Cause识别）
│   ├── rule_engine.py      # YAML 专家规则引擎
│   ├── case_store.py       # SQLite 案例存储
│   ├── agent.py            # 主 Agent（编排各模块）
│   └── llm_client.py       # LLM 客户端（OpenAI 兼容）
├── ui/
│   └── streamlit_app.py    # Web 界面
├── knowledge/
│   ├── rules/              # YAML 规则文件
│   │   ├── ngap.yaml       # NGAP 规则（5条）
│   │   └── nas_5gs.yaml    # NAS-5GS 规则（5条）
│   └── protocol_fields/    # 协议字段说明
├── data/                   # 案例数据库（自动生成）
├── tests/                  # 单元测试
├── samples/                # 示例 pcap 文件
├── pyproject.toml          # 项目元信息与依赖
├── .env.example            # 环境配置模板
└── README.md               # 项目说明
```

---

*文档版本：v0.1.0 | 最后更新：2026-05-28*
