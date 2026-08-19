# 核心网信令分析Agent

一个本地运行的核心网信令分析工具，支持分析4G/5G/IMS信令失败原因。

## 功能特性

- 📡 **本地运行**：所有数据处理在本地完成，保护敏感数据
- 🔍 **智能分析**：结合专家规则库、历史案例库和LLM推理
- 📊 **多协议支持**：支持NGAP、NAS-5GS、S1AP、NAS-EPS、Diameter、GTPv2、PFCP、SIP等
- 💾 **知识迭代**：支持保存分析结果为案例，生成新规则草稿
- 🖥️ **多种界面**：CLI命令行工具 + Streamlit Web界面
- 🛡️ **安全可靠**：敏感数据默认脱敏，不依赖外部服务

## 快速开始

### 环境要求

1. **Python 3.10+**
2. **Wireshark** (包含tshark命令行工具)
3. **可选：LLM API** (OpenAI兼容API，用于详细分析)

### 安装

```bash
# 克隆项目
git clone <repository-url>
cd core-signal-agent

# 安装依赖
pip install -e .

# 复制环境配置
cp .env.example .env
# 编辑.env文件，配置LLM API等参数
```

### 配置

编辑 `.env` 文件：

```bash
# LLM配置（可选）
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=sk-your-api-key-here

# 本地配置
TSHARK_PATH=/usr/local/bin/tshark  # macOS
# TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe  # Windows
DEFAULT_WINDOW=20
CASE_DB_PATH=data/cases.sqlite
```

### CLI使用

```bash
# 测试环境
python -m app.main test

# 分析抓包文件（不使用LLM）
python -m app.main analyze sample.pcapng --frame 1532

# 使用LLM生成详细报告
python -m app.main analyze sample.pcapng --frame 1532 --llm

# 查看帮助
python -m app.main --help
```

### Web界面使用

```bash
# 启动Streamlit界面
streamlit run ui/streamlit_app.py
```

然后在浏览器中打开 `http://localhost:8501`

## 使用流程

1. **在Wireshark中查看异常信令**
   - 找到异常消息的 `frame.number`
   - 记录下pcap文件路径

2. **使用Agent分析**
   - 上传pcap文件
   - 输入目标帧号
   - 点击"开始分析"

3. **查看分析结果**
   - 协议识别结果
   - 匹配的专家规则
   - 相似历史案例
   - 详细分析报告

4. **保存结果**
   - 保存为历史案例供后续参考
   - 生成新规则草稿丰富知识库

## 项目结构

```
core-signal-agent/
├── app/                    # 核心模块
│   ├── __init__.py
│   ├── main.py            # CLI入口
│   ├── config.py          # 配置管理
│   ├── packet_parser.py   # 抓包解析
│   ├── normalizer.py      # 信令标准化
│   ├── rule_engine.py     # 专家规则引擎
│   ├── case_store.py      # 历史案例库
│   ├── agent.py           # 主Agent
│   └── llm_client.py      # LLM客户端
├── ui/
│   └── streamlit_app.py   # Web界面
├── knowledge/             # 知识库
│   ├── rules/             # 专家规则
│   │   ├── ngap.yaml
│   │   └── nas_5gs.yaml
│   └── protocol_fields/   # 协议字段说明
├── data/                  # 数据目录
│   └── cases.sqlite       # 案例数据库
├── tests/                 # 测试
├── samples/               # 示例文件
├── pyproject.toml         # 项目配置
├── .env.example           # 环境配置示例
└── README.md              # 本文档
```

## 专家规则库

项目包含10条初始专家规则，覆盖：

### 5G规则 (5条)
1. NGAP PDU Session Resource Setup 失败，radioNetwork unspecified
2. NGAP UE Context Release，transport资源不可用
3. NGAP Handover Preparation Failure，radioNetwork原因
4. NGAP Initial Context Setup Failure，protocol错误
5. NGAP PDU Session Resource Setup 失败，transport资源不可用

### NAS-5GS规则 (5条)
6. Registration Reject，Cause #15 (No Suitable Cells In Tracking Area)
7. Registration Reject，Cause #11 (PLMN Not Allowed)
8. PDU Session Establishment Reject，Cause #28 (Requested service option not subscribed)
9. Service Reject，Cause #7 (EPS services not allowed)
10. Authentication Reject，Cause #21 (Synch failure)

## 开发指南

### 添加新协议支持

1. 在 `normalizer.py` 中添加协议识别逻辑
2. 在 `knowledge/rules/` 中添加协议规则文件
3. 在 `knowledge/protocol_fields/` 中添加协议字段说明
4. 更新 `PROTOCOL_PROCEDURE_MAP` 和匹配函数

### 添加新规则

编辑对应的YAML规则文件，格式如下：

```yaml
- id: unique_rule_id
  title: 规则标题
  domain: 5GC/4GC/IMS
  protocol: 协议名称
  match:
    procedure: 流程名
    message_type: 消息类型
    result: failure/success
    cause_category: 原因类别
    cause_value: 原因值
  possible_causes:
    - title: 可能原因1
      confidence: high/medium/low
      evidence:
        - 证据1
        - 证据2
      checks:
        - 检查项1
        - 检查项2
  missing_info:
    - 缺失信息1
    - 缺失信息2
```

### 运行测试

```bash
# 运行所有测试
pytest

# 运行特定测试
pytest tests/test_normalizer.py

# 生成测试覆盖率报告
pytest --cov=app tests/
```

## 技术架构

### 核心模块

1. **抓包解析模块** (`packet_parser.py`)
   - 使用tshark解析pcap文件
   - 提取指定帧和上下文报文

2. **信令标准化模块** (`normalizer.py`)
   - 将Wireshark原始字段转换为业务统一字段
   - 识别协议、流程、消息类型、Cause等

3. **专家规则引擎** (`rule_engine.py`)
   - 加载和匹配YAML规则库
   - 支持精确匹配和模糊匹配

4. **历史案例库** (`case_store.py`)
   - 基于SQLite的案例存储和检索
   - 支持相似案例搜索

5. **Agent主模块** (`agent.py`)
   - 协调各模块完成分析任务
   - 生成分析报告
   - 支持保存案例和生成规则草稿

6. **LLM客户端** (`llm_client.py`)
   - 调用大模型生成详细分析报告
   - 支持OpenAI兼容API

### 数据流

```
Wireshark pcap文件
    ↓
tshark解析 (JSON)
    ↓
信令标准化 (统一字段)
    ↓
规则匹配 + 案例检索
    ↓
Agent分析 (规则+案例+LLM)
    ↓
结构化分析报告
    ↓
保存为案例/生成新规则
```

## 安全与隐私

- 🔒 **本地处理**：所有抓包文件在本地解析，不上传云端
- 🎭 **数据脱敏**：发送给LLM前进行字段级摘要和脱敏
- 🔐 **配置安全**：API密钥等敏感信息通过环境变量管理
- 📁 **文件隔离**：临时文件自动清理，中间产物隔离存储

## 后续计划

### 短期计划
1. 增加更多协议支持 (S1AP, Diameter, GTPv2, PFCP, SIP)
2. 优化规则匹配算法
3. 增加批量分析功能
4. 导出分析报告为PDF/Word

### 中期计划
1. Wireshark插件集成
2. 向量检索相似案例
3. 配置知识库集成
4. 多模型支持 (本地Ollama模型)

### 长期计划
1. 自动流程识别
2. 实时监控和告警
3. 多用户协作平台
4. 机器学习模型训练

## 常见问题

### Q: tshark找不到怎么办？
A: 确保已安装Wireshark，并在`.env`文件中配置正确的`TSHARK_PATH`

### Q: 没有LLM API能使用吗？
A: 可以，Agent会使用规则库和案例库进行分析，只是报告会相对简单

### Q: 如何添加自己的专家经验？
A: 通过Web界面的"保存为案例"和"生成规则草稿"功能，或直接编辑YAML规则文件

### Q: 支持哪些抓包文件格式？
A: 支持Wireshark的`.pcap`和`.pcapng`格式

### Q: 如何贡献代码？
A: 欢迎提交Issue和Pull Request，请确保通过测试并更新文档

## 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 联系方式

如有问题或建议，请通过GitHub Issues提交。

---

**核心网信令分析Agent** - 让信令排障更智能、更高效！