# 文件威胁情报分析功能说明

## 功能概述

MCP-IRT 项目已成功增强，新增了文件威胁情报分析功能。当系统检测到可疑进程并定位到可疑文件时，会自动通过文件哈希值（SHA256）查询威胁情报平台，获取文件威胁评级并输出到报告中。

### 主要特性

- ✅ **哈希查询方式**：仅上传文件SHA256哈希值，不上传文件内容，保护隐私
- ✅ **多平台支持**：集成 VirusTotal 和微步在线 ThreatBook 两大威胁情报平台
- ✅ **智能文件识别**：自动识别 exe、scr、ps1、elf、sh、dll、so、php、jsp、aspx 等可疑文件类型
- ✅ **文件大小限制**：最大100MB，避免处理超大文件
- ✅ **速率限制**：遵守API限流规则（4请求/分钟）
- ✅ **缓存机制**：避免重复查询同一文件哈希
- ✅ **详细报告**：支持 Markdown 和 HTML 格式，包含检出率、恶意软件家族、标签等详细信息

## 配置说明

### 1. 配置文件路径

配置文件位于：`config/config.json`

### 2. 文件分析配置

新增的 `file_analysis` 配置段已自动添加到 `threat_intel` 配置中：

```json
"threat_intel": {
  "enabled": true,
  "virustotal_api_key": "YOUR_VT_API_KEY",
  "abuseipdb_api_key": "YOUR_ABUSEIPDB_API_KEY",
  "file_analysis": {
    "enabled": true,
    "max_file_size_mb": 100,
    "upload_method": "hash_only",
    "analyzable_extensions": [
      ".exe", ".scr", ".ps1", ".elf", ".sh",
      ".dll", ".so", ".php", ".jsp", ".aspx",
      ".bat", ".cmd", ".vbs", ".jar"
    ],
    "platforms": {
      "virustotal": {
        "enabled": true
      },
      "threatbook": {
        "enabled": true,
        "api_key": "",
        "api_endpoint": "https://api.threatbook.cn/v3/file/report"
      }
    },
    "rate_limiting": {
      "requests_per_minute": 4,
      "sleep_between_requests": 0.5
    }
  }
}
```

### 3. 配置参数说明

| 参数 | 类型 | 说明 | 默认值 |
|------|------|------|--------|
| `enabled` | boolean | 是否启用文件威胁情报分析 | true |
| `max_file_size_mb` | integer | 最大文件大小限制（MB） | 100 |
| `upload_method` | string | 上传方式（固定为 hash_only） | "hash_only" |
| `analyzable_extensions` | array | 可分析的文件扩展名列表 | [".exe", ".scr", ...] |
| `platforms.virustotal.enabled` | boolean | 是否启用 VirusTotal | true |
| `platforms.threatbook.enabled` | boolean | 是否启用 ThreatBook | true |
| `platforms.threatbook.api_key` | string | ThreatBook API密钥 | "" |
| `rate_limiting.requests_per_minute` | integer | 每分钟最大请求数 | 4 |
| `rate_limiting.sleep_between_requests` | float | 请求间隔（秒） | 0.5 |

## 获取 API 密钥

### VirusTotal

1. 访问 [VirusTotal](https://www.virustotal.com/)
2. 注册/登录账户
3. 前往 [API Key页面](https://www.virustotal.com/gui/my-apikey)
4. 复制API密钥到 `config.json` 的 `virustotal_api_key` 字段

**注意**：免费版限制 4 请求/分钟

### 微步在线 ThreatBook

1. 访问 [微步在线](https://x.threatbook.cn/)
2. 注册/登录账户
3. 前往API管理页面
4. 复制API密钥到 `config.json` 的 `threat_intel.file_analysis.platforms.threatbook.api_key` 字段

## 使用方法

### 基本使用

文件威胁情报分析功能已集成到主工作流中，无需额外操作。只需正常运行 MCP-IRT：

```bash
# 本地分析
python src/main.py --local

# 远程分析（Linux SSH）
python src/main.py --host 192.168.1.100 --username root --password PASSWORD

# 远程分析（Windows WinRM）
python src/main.py --host 192.168.1.101 --username Administrator --password PASSWORD --protocol winrm
```

### 工作流程

1. **脚本执行**：系统执行安全检查脚本（如 check_backdoor_signatures.sh、check_persistence.sh）
2. **文件提取**：从脚本输出中提取可疑文件路径
3. **哈希计算**：通过远程命令计算文件的 SHA256 哈希值
4. **文件大小检查**：跳过超过 100MB 的文件
5. **威胁情报查询**：
   - 查询 VirusTotal API（如果启用）
   - 查询 ThreatBook API（如果启用）
6. **结果汇总**：将分析结果添加到报告中

### 执行日志示例

```
[*] 执行文件威胁情报分析...
  [*] 发现 2 个可疑文件
  [*] 计算 2 个可疑文件的哈希值...
    [+] shell.php: a1b2c3d4e5f6g7h8... (4.2KB)
    [+] evil.exe: 1234567890abcdef... (102.4KB)
  [*] 文件威胁情报分析: 发现 2 个可疑文件
  [1/2] 分析 shell.php (a1b2c3d4e5f6g7h8...)... ⚠️  恶意 (威胁分数: 88)
  [2/2] 分析 evil.exe (1234567890abcdef...)... ⚠️  恶意 (威胁分数: 95)
  [*] 文件威胁情报分析完成: 2 个文件, 2 个恶意文件
```

## 报告格式

### Markdown 报告

报告中会新增"文件威胁情报分析"部分：

#### 表格汇总

| 文件路径 | SHA256（前16位） | 威胁分数 | 状态 | 检出率 | 来源 |
|---------|----------------|---------|------|-------|------|
| /tmp/evil.exe | abcd1234efgh5678 | 95 | 🔴 **恶意** | 45/68 | VirusTotal, ThreatBook |

#### 详细分析

对于恶意文件，报告会包含：
- 完整SHA256哈希
- 威胁分数
- 文件类型
- VirusTotal检出率和百分比
- 标签（如：trojan, backdoor, meterpreter）
- ThreatBook严重度和置信度
- 恶意软件家族（如：Trojan.Metasploit）
- 处置建议

### HTML 报告

HTML报告包含相同的信息，并使用颜色编码：
- 🔴 红色：恶意文件
- 🟢 绿色：正常文件

## 注意事项

### 隐私和安全

- ✅ **仅上传哈希**：本功能不会上传任何文件内容，仅上传 SHA256 哈希值
- ✅ **白名单机制**：IRT 工具自身文件会被自动排除，不会被分析
- ✅ **日志安全**：日志中只记录文件路径和哈希，不记录文件内容

### API 限制

- **VirusTotal 免费版**：4 请求/分钟，500 请求/天
- **ThreatBook**：请参考平台文档了解限制

如果超出限制，系统会自动：
- 等待并重试（遇到 429 错误）
- 继续处理剩余文件（避免整体失败）

### 性能考虑

- 每个文件哈希查询耗时约 0.5-2 秒
- 大量可疑文件可能导致分析时间较长
- 建议在非生产环境测试时先设置较小的 `max_file_size_mb` 值

## 故障排查

### 问题1：文件威胁情报分析未启用

**原因**：配置未正确设置或 API 密钥缺失

**解决**：
1. 检查 `config.json` 中 `file_analysis.enabled` 是否为 `true`
2. 确认至少一个平台（VirusTotal 或 ThreatBook）已启用
3. 确认对应平台的 API 密钥已正确配置

### 问题2：无法计算文件哈希

**原因**：文件不存在、权限不足、或文件过大

**解决**：
1. 检查文件是否存在：`ls -la /path/to/file`（Linux）或 `Test-Path "C:\path\to\file"`（Windows）
2. 检查文件权限：确保有读取权限
3. 检查文件大小：`du -h /path/to/file`（Linux）或 `(Get-Item "C:\path\to\file").Length / 1MB`（Windows）

### 问题3：API 查询失败

**错误信息**：`VirusTotal API 配额已用完` 或 `ThreatBook API 配额已用完`

**解决**：
1. 等待配额重置（通常每天重置）
2. 考虑升级到付费版本
3. 调整 `rate_limiting` 配置以降低请求频率

### 问题4：文件未被检测为可疑

**原因**：文件路径不在检测模式中

**解决**：
检查 `threat_detector.py` 中的 `extract_suspicious_files_from_output()` 方法，确认文件路径匹配预定义的可疑路径模式。

## 技术实现

### 修改的文件

1. **config/config.json**：添加 `file_analysis` 配置段
2. **src/threat_intel.py**：
   - 新增 `is_file_analysis_enabled()` 方法
   - 新增 `analyze_file_hash()` 方法
   - 新增 `batch_analyze_file_hashes()` 方法
   - 新增 `_query_virustotal_file()` 方法
   - 新增 `_query_threatbook_file()` 方法
3. **src/threat_detector.py**：
   - 新增 `extract_suspicious_files_from_output()` 方法
   - 新增 `is_analyzable_file()` 方法
4. **src/executor.py**：
   - 新增 `_calculate_file_hashes()` 方法
   - 新增 `_perform_file_threat_intelligence_analysis()` 方法
   - 在 `execute_ir_workflow()` 中集成文件分析流程
5. **src/reporter.py**：
   - Markdown 报告：添加文件威胁情报分析段落
   - HTML 报告：添加文件威胁情报分析表格和详细分析

### API 集成

#### VirusTotal File API

- **Endpoint**: `GET https://www.virustotal.com/api/v3/files/{sha256}`
- **认证**: Header `x-apikey: {api_key}`
- **返回字段**：
  - `last_analysis_stats`: 检出统计（malicious, suspicious, undetected, harmless）
  - `type_description`: 文件类型
  - `tags`: 威胁标签
  - `size`: 文件大小

#### ThreatBook File API

- **Endpoint**: `GET https://api.threatbook.cn/v3/file/report?apikey={key}&resource={sha256}`
- **返回字段**：
  - `severity`: 严重度（high, medium, low）
  - `confidence`: 置信度（0-100）
  - `malware_family`: 恶意软件家族
  - `tags`: 威胁标签
  - `judgments`: 判定结果

## 测试建议

### 1. 功能测试

使用已知恶意文件哈希测试（从 VirusTotal 公开样本获取）：

```python
# 测试哈希（EICAR测试文件）
test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```

### 2. 集成测试

1. 在测试环境创建可疑文件：
   ```bash
   # Linux
   echo "test" > /tmp/suspicious_test.sh

   # Windows
   echo "test" > C:\Windows\Temp\suspicious_test.ps1
   ```

2. 运行 MCP-IRT 分析
3. 检查报告中是否包含文件威胁情报分析结果

### 3. 性能测试

监控不同数量的可疑文件对分析时间的影响：
- 1 个文件：约 1-2 秒
- 10 个文件：约 5-10 秒
- 100 个文件：约 50-100 秒

## 后续优化建议

1. **持久化缓存**：将哈希查询结果缓存到文件，避免重复分析已知文件
2. **批量查询优化**：使用 VirusTotal 的批量查询 API（付费版）
3. **更多威胁情报源**：集成 AlienVault OTX、Shodan 等平台
4. **文件上传选项**：对于未知文件，提供完整文件上传选项（需用户确认）
5. **自定义可疑路径**：支持通过配置文件自定义可疑文件路径模式

## 联系支持

如有问题或建议，请：
1. 查看项目 README.md
2. 检查 GitHub Issues
3. 提交新的 Issue 报告问题

---

**版本**：v1.0
**更新日期**：2025-12-20
**功能状态**：✅ 已实现并测试
