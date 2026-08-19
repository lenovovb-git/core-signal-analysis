# 核心网信令分析Agent - 使用示例

## 示例文件说明

本目录包含用于测试和演示的示例文件。由于实际抓包文件较大且可能包含敏感信息，这里提供一些模拟数据和测试用例。

### 文件结构

```
samples/
├── README.md              # 本文档
├── test_ngap_failure.json # NGAP失败示例（模拟数据）
├── test_nas_reject.json   # NAS拒绝示例（模拟数据）
└── sample_analysis.md     # 分析结果示例
```

## 示例1：NGAP PDU Session Resource Setup 失败

### 场景描述
- **协议**: NGAP
- **消息**: PDUSessionResourceSetupResponse
- **结果**: 失败
- **原因**: radioNetwork unspecified (无线网络未指定原因)

### 模拟数据 (`test_ngap_failure.json`)

```json
{
  "frame": {
    "frame.number": "1532",
    "frame.time": "2024-05-25 10:30:15.123456"
  },
  "sctp": {
    "sctp.srcport": "38412",
    "sctp.dstport": "38412"
  },
  "ngap": {
    "ngap.ProcedureCode": "19",
    "ngap.message_type": "PDUSessionResourceSetupResponse",
    "ngap.CauseGroup": "radioNetwork",
    "ngap.Cause_value": "unspecified",
    "ngap.RAN_UE_NGAP_ID": "12345",
    "ngap.AMF_UE_NGAP_ID": "67890",
    "ngap.PDU_Session_ID": "1",
    "ngap.S_NSSAI": "SST:1,SD:010203"
  },
  "_ws.col.Info": "PDUSessionResourceSetupResponse, Cause: radioNetwork (unspecified)"
}
```

### 分析结果
Agent会匹配到规则 `ngap_pdu_session_resource_setup_radio_unspecified`，给出可能原因：
1. gNB未配置对应QoS或DRB模板
2. SMF下发参数与接入侧能力不匹配
3. 空口资源不足导致DRB建立失败

## 示例2：NAS-5GS Registration Reject

### 场景描述
- **协议**: NAS-5GS
- **消息**: RegistrationReject
- **结果**: 失败
- **原因**: Cause #15 (No Suitable Cells In Tracking Area)

### 模拟数据 (`test_nas_reject.json`)

```json
{
  "frame": {
    "frame.number": "2456",
    "frame.time": "2024-05-25 11:45:30.789012"
  },
  "nas-5gs": {
    "nas_5gs.message_type": "RegistrationReject",
    "nas_5gs.nmm.cause": "15",
    "nas_5gs.nmm.5gs_mobile_identity": "SUCI:0-001-01-0-0-1234567890",
    "nas_5gs.nmm.last_visited_registered_tai": "PLMN:001-01, TAC:1234"
  },
  "_ws.col.Info": "Registration reject, Cause: No Suitable Cells In Tracking Area (15)"
}
```

### 分析结果
Agent会匹配到规则 `nas_5gs_registration_reject_cause_15`，给出可能原因：
1. TAI不在AMF的服务范围内
2. gNB与AMF的N2接口未建立
3. TAI配置错误或未在AMF中开通

## 使用示例文件测试

### 方法1：使用模拟数据测试

```bash
# 进入项目目录
cd core-signal-agent

# 创建测试脚本
python -c "
import json
from app.agent import CoreSignalAgent

# 加载模拟数据
with open('samples/test_ngap_failure.json', 'r') as f:
    packet_data = json.load(f)

# 创建Agent（不使用LLM）
agent = CoreSignalAgent(use_llm=False)

# 模拟分析结果
result = {
    'selected_packet': packet_data,
    'normalized': {
        'protocol': 'NGAP',
        'procedure': 'PDU Session Resource Setup',
        'message_type': 'PDUSessionResourceSetupResponse',
        'result': 'failure',
        'cause_category': 'radioNetwork',
        'cause_value': 'unspecified'
    }
}

# 匹配规则
matched = agent.rule_engine.match_rules(result['normalized'], 'exact')
print(f'匹配到 {len(matched)} 条规则')
for rule in matched:
    print(f'  - {rule[\"title\"]} (匹配度: {rule[\"score\"]:.2f})')
"
```

### 方法2：使用真实抓包文件

1. **准备真实抓包文件**
   - 使用Wireshark抓取核心网信令
   - 保存为 `.pcapng` 格式
   - 注意脱敏敏感信息

2. **使用Agent分析**
   ```bash
   python -m app.main analyze your_capture.pcapng --frame 100 --llm
   ```

3. **查看分析结果**
   - CLI会输出结构化分析报告
   - Web界面提供更丰富的可视化

## 创建自己的测试用例

### 步骤1：创建模拟数据文件

```json
{
  "frame": {
    "frame.number": "1000",
    "frame.time": "2024-01-01 12:00:00.000000"
  },
  "protocol_layer_1": {
    "field1": "value1",
    "field2": "value2"
  },
  "protocol_layer_2": {
    "field3": "value3"
  },
  "_ws.col.Info": "Description of the packet"
}
```

### 步骤2：添加对应规则

编辑 `knowledge/rules/` 目录下的YAML文件，添加新规则。

### 步骤3：测试规则匹配

```python
from app.rule_engine import RuleEngine
from app.normalizer import normalize_packet

# 加载规则
engine = RuleEngine('knowledge/rules')

# 标准化数据
normalized = normalize_packet(packet_data)

# 匹配规则
matched = engine.match_rules(normalized, 'exact')
```

## 性能测试

### 测试1：规则匹配性能
```bash
python -c "
import time
from app.rule_engine import RuleEngine

engine = RuleEngine('knowledge/rules')

# 测试1000次匹配
start = time.time()
for i in range(1000):
    packet = {
        'protocol': 'NGAP',
        'procedure': 'PDU Session Resource Setup',
        'message_type': 'PDUSessionResourceSetupResponse',
        'result': 'failure',
        'cause_category': 'radioNetwork',
        'cause_value': 'unspecified'
    }
    engine.match_rules(packet, 'exact')

elapsed = time.time() - start
print(f'1000次匹配耗时: {elapsed:.3f}秒, 平均: {elapsed/1000*1000:.1f}毫秒/次')
"
```

### 测试2：案例检索性能
```bash
python -c "
import time
from app.case_store import CaseStore

store = CaseStore('data/cases.sqlite')

# 测试检索性能
start = time.time()
cases = store.search_cases(
    protocol='NGAP',
    procedure='PDU Session Resource Setup',
    message_type='PDUSessionResourceSetupResponse'
)
elapsed = time.time() - start

print(f'案例检索耗时: {elapsed:.3f}秒')
print(f'找到 {len(cases)} 条案例')
"
```

## 集成测试

### 完整流程测试
```bash
# 创建测试脚本
cat > test_full_flow.py << 'EOF'
import json
import tempfile
from pathlib import Path
from app.agent import CoreSignalAgent

# 创建临时pcap文件（模拟）
with tempfile.NamedTemporaryFile(suffix='.pcapng', delete=False) as f:
    temp_pcap = f.name

print(f"使用临时文件: {temp_pcap}")

# 创建Agent
agent = CoreSignalAgent(use_llm=False)

try:
    # 测试分析流程
    result = agent.analyze(
        pcap_path=temp_pcap,
        frame_number=1,
        window=10,
        match_mode='exact'
    )
    
    print("分析完成!")
    print(f"协议: {result.get('summary', {}).get('protocol', 'N/A')}")
    print(f"匹配规则数: {result.get('summary', {}).get('matched_rules_count', 0)}")
    
except Exception as e:
    print(f"分析失败: {e}")

# 清理
Path(temp_pcap).unlink(missing_ok=True)
EOF

# 运行测试
python test_full_flow.py
```

## 注意事项

1. **数据安全**：真实抓包文件可能包含敏感信息，建议在测试环境中使用
2. **文件大小**：大文件分析可能需要较长时间，建议使用小样本测试
3. **环境依赖**：确保tshark可用，Python环境配置正确
4. **规则更新**：添加新规则后需要重启Agent或重新加载规则库

## 贡献示例

欢迎提交更多示例用例：
1. 常见故障场景
2. 不同协议组合
3. 复杂流程分析
4. 性能优化案例

提交方式：创建Pull Request或通过Issues分享。