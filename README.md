# MCP-IRT: 自动化安全应急响应工具

一个自动化的安全应急响应工具，支持本地和远程主机的安全检查、威胁排查和响应处置，集成威胁情报分析和 AI 驱动的安全事件分析能力。

## 主要功能

### 核心功能
- **本地 + 远程模式**: 支持直接扫描本地系统或远程连接目标主机
- **跨平台支持**: 支持 Linux 和 Windows 操作系统
- **远程连接**: 支持 SSH（Linux）和 WinRM（Windows）
- **自动化检查**: 自动执行多项安全检查脚本
- **智能分析**: 自动识别可疑进程、网络连接、计划任务等
- **响应处置**: 支持进程终止、IP 阻断等响应动作
- **报告生成**: 自动生成详细的 Markdown 格式应急响应报告

### 高级功能
- **威胁情报集成**:
  - **IP情报查询**: 集成 VirusTotal 和 AbuseIPDB，自动查询外部连接IP的威胁信誉
  - **文件威胁分析**: 自动分析可疑文件，支持三种模式：
    - `hash_only`: 仅查询文件哈希（快速）
    - `file_upload`: 上传文件进行沙箱分析（准确）
    - `auto`: 智能模式，先查哈希，未找到则自动上传文件（推荐）
  - 支持平台：VirusTotal、微步在线 ThreatBook
  - 智能过滤：自动排除内网IP、公共DNS、广播地址等无需查询的地址
- **AI 驱动分析**: 支持 OpenAI GPT-4、Anthropic Claude、Qwen，智能分析威胁模式
- **行为分析**: 基于行为模式的异常检测和威胁识别
- **MCP 协议支持**: 可作为 MCP Server 与 Claude Desktop 集成使用

## 项目结构

```
mcp-irt/
├── src/                              # 源代码目录
│   ├── main.py                      # 主程序入口
│   ├── connector.py                 # 远程连接模块（SSH/WinRM）
│   ├── executor.py                  # 脚本执行引擎
│   ├── reporter.py                  # 报告生成模块
│   ├── config.py                    # 配置管理
│   ├── threat_intel.py              # 威胁情报集成
│   ├── ai_analyzer.py               # AI 驱动分析
│   ├── behavior_analyzer.py         # 行为分析模块
│   ├── threat_detector.py           # 威胁检测引擎
│   └── response_engine.py           # 自动响应引擎
├── scripts/                          # 应急响应脚本库
│   ├── linux/                       # Linux 安全检查脚本
│   │   ├── check_processes.sh       # 进程检查
│   │   ├── check_network.sh         # 网络检查
│   │   ├── check_cron.sh            # 计划任务检查
│   │   ├── check_logs.sh            # 日志分析
│   │   ├── check_persistence.sh     # 持久化机制检测
│   │   ├── kill_process.sh          # 终止进程
│   │   └── block_ip.sh              # IP 阻断
│   └── windows/                     # Windows 安全检查脚本
│       ├── check_processes.ps1      # 进程检查
│       ├── check_network.ps1        # 网络检查
│       ├── check_tasks.ps1          # 计划任务检查
│       ├── check_logs.ps1           # 事件日志分析
│       ├── check_persistence.ps1    # 持久化机制检测
│       ├── check_rdp.ps1            # RDP 配置检查
│       ├── check_defender.ps1       # Windows Defender 检查
│       ├── check_powershell_history.ps1  # PowerShell 历史分析
│       ├── check_user_security.ps1  # 用户账户审计
│       ├── kill_process.ps1         # 终止进程
│       └── block_ip.ps1             # IP 阻断
├── config/                           # 配置文件目录
│   ├── config.json                  # 主配置文件
│   └── examples.md                  # 配置示例
├── reports/                          # 报告输出目录
├── logs/                             # 应用程序日志
├── mcp_server.py                     # MCP Server 实现
├── run.bat                           # Windows 快速启动脚本
├── requirements.txt                  # Python 依赖
└── README.md                         # 项目说明文档
```

## 安装部署

### 环境要求

- Python 3.7+
- 操作系统: Windows / Linux / macOS

### 安装依赖

```bash
cd mcp-irt
pip install -r requirements.txt
```

**依赖包说明**:
- `paramiko>=3.4.0` - SSH 连接库
- `pywinrm>=0.4.3` - Windows 远程管理
- `requests>=2.31.0` - HTTP 请求库
- `requests-ntlm>=1.2.0` - NTLM 认证
- `python-dateutil>=2.8.2` - 日期处理
- `openai>=1.0.0` - OpenAI API（可选）
- `anthropic>=0.18.0` - Anthropic API（可选）

### 配置目标主机

**Linux 主机**:
```bash
# 确保 SSH 服务已启动
sudo systemctl start sshd

# 或配置 SSH 密钥认证
ssh-copy-id user@target-host
```

**Windows 主机**:
```powershell
# 启用 WinRM
Enable-PSRemoting -Force

# 配置防火墙规则
netsh advfirewall firewall add rule name="WinRM HTTP" dir=in action=allow protocol=TCP localport=5985

# 设置 WinRM 服务为自动启动
Set-Service WinRM -StartupType Automatic
Start-Service WinRM
```

## 基本用法

### 快速开始

**连接 Linux 主机**:
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password "your_password"
```

**连接 Windows 主机**:
```bash
python src/main.py \
  --host 192.168.1.200 \
  --username Administrator \
  --password "your_password" \
  --protocol winrm
```

**本地模式（直接扫描本机）**:
```bash
# 本地模式无需提供主机地址和凭据
python src/main.py --local
```

本地模式特点：
- 无需远程连接，直接在本地系统执行检查
- 自动检测本地操作系统类型（Windows/Linux）
- 无需配置 SSH 或 WinRM
- 执行速度更快，适合快速自查
- 所有分析功能（本地检测、AI 分析、威胁情报）均可用

### 命令行参数

| 参数 | 必需 | 说明 |
|------|------|------|
| `--local` | 否 | 启用本地模式，直接扫描本机（启用后无需 --host 和 --username） |
| `--host` | 条件 | 目标主机地址（远程模式必需） |
| `--username` | 条件 | 登录用户名（远程模式必需） |
| `--password` | 条件 | 登录密码（或使用 --key-file） |
| `--key-file` | 条件 | SSH 私钥文件路径 |
| `--os-type` | 否 | 操作系统类型（linux/windows），默认自动检测 |
| `--protocol` | 否 | 连接协议（ssh/winrm），默认根据OS自动选择 |
| `--port` | 否 | 连接端口（SSH默认22，WinRM默认5985） |
| `--threat-desc` | 否 | 威胁描述，默认为"常规安全检查" |
| `--config` | 否 | 配置文件路径（默认 config/config.json） |
| `--output` | 否 | 报告输出路径（默认自动生成） |
| `--format` | 否 | 报告格式（md 或 html，默认 md） |

### 报告格式

工具支持两种报告格式：

**Markdown 格式（默认）**:
```bash
python src/main.py --local --format md
# 或省略 --format 参数（默认为 md）
python src/main.py --local
```

**HTML 格式**:
```bash
python src/main.py --local --format html
```

HTML报告特点：
- 美观的响应式设计，支持移动端浏览
- 彩色卡片式摘要统计
- 高亮可疑内容，便于快速定位威胁
- 表格展示威胁情报数据
- 支持浏览器打印，方便存档
- 单文件HTML，内嵌CSS样式，无需外部依赖

**自定义输出路径**:
```bash
# Markdown格式
python src/main.py --local --output custom_report.md

# HTML格式
python src/main.py --local --format html --output custom_report.html
```

## API 配置（可选）

### 威胁情报 API

如需使用威胁情报功能，需在 `config/config.json` 中配置 API 密钥：

```json
{
  "threat_intel": {
    "enabled": true,
    "virustotal_api_key": "YOUR_VT_API_KEY",
    "abuseipdb_api_key": "YOUR_ABUSEIPDB_API_KEY",
    "file_analysis": {
      "enabled": true,
      "upload_method": "auto",
      "max_file_size_mb": 100,
      "platforms": {
        "virustotal": {
          "enabled": true
        },
        "threatbook": {
          "enabled": true,
          "api_key": "YOUR_THREATBOOK_API_KEY"
        }
      }
    }
  }
}
```

**获取 API 密钥**：
- **VirusTotal**: [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
  - 免费版：4 请求/分钟，500 请求/天
- **AbuseIPDB**: [https://www.abuseipdb.com/api](https://www.abuseipdb.com/api)
- **微步在线 ThreatBook**: [https://x.threatbook.cn/](https://x.threatbook.cn/)

**文件分析模式说明**：

| 模式 | 说明 | 优点 | 缺点 | 适用场景 |
|------|------|------|------|----------|
| `hash_only` | 仅查询文件哈希 | 快速（1-2秒），节省API配额 | 对未知样本无效 | 已知恶意软件检测 |
| `file_upload` | 总是上传文件进行沙箱分析 | 最准确，可检测未知样本 | 慢（20-70秒），消耗API配额 | 高安全要求场景 |
| `auto` | 先查哈希，未找到则上传 | 平衡速度和准确性 | - | **推荐使用** |

配置后，工具会自动：
- ✅ **IP 威胁情报**: 查询外部连接 IP 的威胁评分和声誉信息
- ✅ **文件威胁情报**:
  - 自动提取可疑文件（exe、elf、sh、ps1、php、jsp等）
  - 计算文件 SHA256 哈希值
  - 查询 VirusTotal 和 ThreatBook 数据库
  - 对未知样本自动上传进行沙箱分析（auto模式）
  - 显示详细的检出率、恶意软件家族、威胁标签
- ✅ **智能过滤**:
  - 排除内网IP（127.x.x.x, 10.x.x.x, 192.168.x.x等）
  - 排除公共DNS（8.8.8.8, 114.114.114.114等）
  - 排除特殊地址（0.0.0.0, 255.255.255.255等）
- ✅ **报告展示**: 在报告中显示威胁情报分析结果

**文件分析支持的文件类型**：
- **可执行文件**: .exe, .scr, .elf, .dll, .so
- **脚本文件**: .sh, .ps1, .bat, .cmd, .vbs, .py, .pl, .rb
- **Web后门**: .php, .jsp, .aspx
- **其他**: .jar

**注意事项**：
- 文件大小限制：100MB（可在配置中调整）
- VirusTotal 免费版限制：4 请求/分钟
- 上传文件进行沙箱分析需要 10-60 秒等待时间
- 仅上传文件哈希（hash_only）或完整文件（file_upload/auto）
- 远程文件会自动下载到本地临时目录进行上传，分析完成后自动清理

### AI 分析 API

如需使用 AI 驱动分析功能，请配置：

```bash
# OpenAI API
export OPENAI_API_KEY="your_api_key_here"

# 或使用 Anthropic Claude API
export ANTHROPIC_API_KEY="your_api_key_here"
```

配置后，工具会自动：
- 使用 GPT-4 或 Claude 分析安全事件
- 生成智能化的威胁评估报告
- 提供定制化的应急响应建议

### MCP Server 模式

作为 MCP Server 与 Claude Desktop 集成：

```bash
# 启动 MCP Server
python mcp_server.py
```

在 Claude Desktop 配置中添加：
```json
{
  "mcpServers": {
    "mcp-irt": {
      "command": "python",
      "args": ["C:/path/to/mcp-irt/mcp_server.py"]
    }
  }
}
```

## 检查项说明

### Linux 检查项

- **进程检查**: 高 CPU/内存占用进程、可疑路径、隐藏进程
- **网络检查**: 监听端口、已建立连接、可疑端口、反向 Shell 特征
- **计划任务**: 系统/用户 crontab、at 任务、systemd timer
- **日志分析**: SSH/sudo/认证日志、暴力破解、异常时段登录
- **持久化检测**: Rootkit、后门、启动项、init.d 脚本

### Windows 检查项

- **进程检查**: 高 CPU/内存占用、未签名进程、可疑路径、隐藏窗口
- **网络检查**: 监听端口、已建立连接、防火墙规则、Hosts 文件
- **计划任务**: Task Scheduler、启动项、注册表、可疑服务
- **日志分析**: 登录失败/成功、账户创建、RDP 连接、特权使用
- **持久化检测**: 12种权限维持机制（注册表、WMI、服务、COM劫持等）
- **RDP 检查**: RDP配置、连接历史、暴力破解检测、证书检测
- **Defender 检查**: 服务状态、实时保护、排除项、威胁历史
- **PowerShell 历史**: 历史记录、可疑命令模式检测、执行策略
- **用户审计**: 账户审计、密码策略、UAC配置、特权账户使用

## 自定义配置

编辑 `config/config.json` 来自定义工作流：

```json
{
  "workflow": {
    "linux": [
      "check_processes",
      "check_network",
      "check_cron",
      "check_logs"
    ],
    "windows": [
      "check_processes",
      "check_network",
      "check_tasks",
      "check_logs"
    ]
  },
  "scripts": {
    "linux": {
      "check_processes": "scripts/linux/check_processes.sh"
    },
    "windows": {
      "check_processes": "scripts/windows/check_processes.ps1"
    }
  },
  "threat_intel": {
    "virustotal_enabled": true,
    "abuseipdb_enabled": true
  },
  "ai_analysis": {
    "enabled": true,
    "provider": "openai",
    "model": "gpt-4"
  }
}
```

## 安全注意事项

1. **权限要求**: 某些检查需要管理员/root 权限
2. **密码安全**: 避免在命令行中直接传递密码，优先使用 SSH 密钥认证
3. **网络安全**: 确保连接通道安全，使用 VPN 或跳板机
4. **取证保护**: 操作前确保已备份关键数据
5. **响应审慎**: 终止进程和阻断 IP 前请仔细确认
6. **API 密钥管理**: 妥善保管威胁情报和 AI API 密钥
7. **合规性**: 确保操作符合法律法规，获得目标系统所有者授权

## 许可证与免责声明

本工具仅供合法的安全测试和应急响应使用。使用者需确保：

1. **授权要求**: 已获得目标系统所有者的明确授权
2. **法律合规**: 遵守当地法律法规和网络安全法
3. **责任承担**: 对使用本工具造成的任何后果负责
4. **禁止滥用**: 禁止将本工具用于非法目的

开发者不对工具的误用或滥用承担任何责任。使用本工具即表示同意本免责声明。

---

**版本**: 1.1.0
**最后更新**: 2025-12-20
