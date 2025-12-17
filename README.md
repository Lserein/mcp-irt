# MCP-IRT: 自动化安全应急响应助手

Automated Incident Response Tool - 一个自动化的安全应急响应工具，支持远程主机的安全检查、威胁排查和响应处置，集成威胁情报分析和 AI 驱动的安全事件分析能力。

## 功能特性

### 核心功能
- **跨平台支持**: 支持 Linux 和 Windows 操作系统
- **多种连接方式**: 支持 SSH（Linux）和 WinRM（Windows）
- **自动化检查**: 自动执行多项安全检查脚本
- **智能分析**: 自动识别可疑进程、网络连接、计划任务等
- **响应处置**: 支持进程终止、IP 阻断等响应动作
- **报告生成**: 自动生成详细的 Markdown 格式应急响应报告
- **取证保存**: 自动保存关键取证数据

### 高级功能
- **威胁情报集成**: 集成 VirusTotal 和 AbuseIPDB，自动查询文件哈希和 IP 信誉
- **AI 驱动分析**: 支持 OpenAI GPT-4 和 Anthropic Claude，智能分析威胁模式
- **行为分析**: 基于行为模式的异常检测和威胁识别
- **高级持久化检测**: 深度检测 rootkit、后门和其他持久化机制
- **进程内存转储**: 支持可疑进程的内存取证
- **MCP 协议支持**: 可作为 MCP Server 与 Claude Desktop 集成使用

## 项目结构

```
mcp-irt/
├── src/                              # 源代码目录
│   ├── main.py                      # 主程序入口，CLI 参数解析和工作流编排
│   ├── connector.py                 # 远程连接模块（SSH/WinRM）
│   ├── executor.py                  # 脚本执行引擎，应急响应工作流管理
│   ├── reporter.py                  # 报告生成模块，Markdown 格式输出
│   ├── config.py                    # 配置管理，加载和管理配置文件
│   ├── threat_intel.py              # 威胁情报集成（VirusTotal/AbuseIPDB）
│   ├── ai_analyzer.py               # AI 驱动分析（OpenAI/Anthropic）
│   ├── behavior_analyzer.py         # 行为分析模块，检测异常行为模式
│   ├── threat_detector.py           # 威胁检测引擎，模式匹配和规则判断
│   └── response_engine.py           # 自动响应引擎，执行处置动作
├── scripts/                          # 应急响应脚本库
│   ├── linux/                       # Linux 安全检查脚本
│   │   ├── check_processes.sh       # 进程检查（高CPU、可疑路径、隐藏进程）
│   │   ├── check_network.sh         # 网络检查（监听端口、可疑连接、反向Shell）
│   │   ├── check_cron.sh            # 计划任务检查（cron/at/systemd timer）
│   │   ├── check_logs.sh            # 日志分析（SSH/sudo/认证日志）
│   │   ├── check_persistence.sh     # 持久化机制检测（rootkit/后门/启动项）
│   │   ├── check_backdoor_signatures.sh  # 后门签名扫描
│   │   ├── check_system_integrity.sh     # 系统完整性验证
│   │   ├── check_user_security.sh        # 用户账户安全分析
│   │   ├── dump_process_memory.sh        # 进程内存转储（取证）
│   │   ├── kill_process.sh               # 终止进程
│   │   └── block_ip.sh                   # IP 阻断（iptables）
│   └── windows/                     # Windows 安全检查脚本
│       ├── check_processes.ps1      # 进程检查（高CPU、未签名、可疑路径）
│       ├── check_network.ps1        # 网络检查（监听端口、可疑连接、防火墙）
│       ├── check_tasks.ps1          # 计划任务检查（Task Scheduler/启动项）
│       ├── check_logs.ps1           # 事件日志分析（登录/用户管理/特权使用）
│       ├── kill_process.ps1         # 终止进程
│       └── block_ip.ps1             # IP 阻断（Windows Firewall）
├── config/                           # 配置文件目录
│   ├── config.json                  # 主配置文件（工作流定义、脚本路径）
│   └── examples.md                  # 配置示例和使用说明
├── reports/                          # 报告输出目录（自动生成）
├── logs/                             # 应用程序日志目录
├── venv/                             # Python 虚拟环境（可选）
├── mcp_server.py                     # MCP Server 实现，支持 Claude Desktop 集成
├── run.bat                           # Windows 快速启动脚本
├── requirements.txt                  # Python 依赖清单
├── README.md                         # 项目说明文档（本文件）
├── QUICKSTART.md                     # 快速上手指南
├── HOW_TO_RUN.md                     # 运行说明
├── USAGE_EXAMPLES.md                 # 使用示例集
├── THREAT_INTEL_GUIDE.md             # 威胁情报集成指南
├── ADVANCED_PERSISTENCE_DETECTION.md # 高级持久化检测指南
├── AI_ANALYSIS_GUIDE.md              # AI 分析使用指南
├── ENHANCED_FEATURES_V2.md           # 增强功能文档
├── CHANGELOG.md                      # 版本更新日志
└── WHATS_NEW.md                      # 新功能说明
```

### 核心模块说明

| 模块 | 功能说明 |
|------|---------|
| `main.py` | CLI 入口，参数解析，工作流协调 |
| `connector.py` | 远程连接管理，支持 SSH 密钥/密码认证和 WinRM |
| `executor.py` | 脚本执行引擎，结果分析，自动响应决策 |
| `reporter.py` | 生成结构化的 Markdown 应急响应报告 |
| `config.py` | 配置加载和管理，支持自定义工作流 |
| `threat_intel.py` | 威胁情报查询（VirusTotal API、AbuseIPDB API）|
| `ai_analyzer.py` | AI 分析接口，支持 GPT-4 和 Claude |
| `behavior_analyzer.py` | 行为模式分析，识别异常活动 |
| `threat_detector.py` | 威胁检测逻辑，规则匹配和评分 |
| `response_engine.py` | 自动响应执行，进程终止、IP 封禁等 |

### 关键脚本说明

#### Linux 脚本
| 脚本 | 检测内容 |
|------|---------|
| `check_processes.sh` | 高 CPU/内存进程、可疑路径、网络监听、隐藏进程 |
| `check_network.sh` | 监听端口、已建立连接、反向 Shell 特征、防火墙规则 |
| `check_cron.sh` | 系统/用户 crontab、at 任务、systemd timer |
| `check_logs.sh` | SSH/sudo/认证日志、暴力破解、异常时段登录 |
| `check_persistence.sh` | Rootkit、后门、启动项、init.d 脚本 |
| `check_backdoor_signatures.sh` | 已知后门签名扫描 |
| `check_system_integrity.sh` | 系统文件完整性校验 |
| `check_user_security.sh` | 用户账户、权限、组成员分析 |
| `dump_process_memory.sh` | 进程内存转储（需 root 权限）|

#### Windows 脚本
| 脚本 | 检测内容 |
|------|---------|
| `check_processes.ps1` | 高 CPU/内存进程、未签名进程、可疑路径、隐藏窗口 |
| `check_network.ps1` | 监听端口、已建立连接、防火墙规则、Hosts 文件 |
| `check_tasks.ps1` | Task Scheduler、启动项、注册表、可疑服务 |
| `check_logs.ps1` | 登录失败/成功、账户锁定、用户创建、RDP 连接 |

## 安装部署

### 1. 环境要求

- Python 3.7+
- 操作系统: Windows / Linux / macOS

### 2. 快速启动（Windows）

使用提供的 `run.bat` 脚本快速启动：

```batch
# 自动检查并安装依赖
cd C:\Users\24767\Desktop\mcp-irt
run.bat

# 按照提示输入主机信息
```

`run.bat` 会自动完成：
- 检查 Python 环境
- 验证并安装缺失的依赖包
- 显示使用示例和帮助信息

### 3. 手动安装依赖

```bash
cd C:\Users\24767\Desktop\mcp-irt
pip install -r requirements.txt
```

**依赖包说明**:
- `paramiko>=3.4.0` - SSH 连接库
- `pywinrm>=0.4.3` - Windows 远程管理
- `requests>=2.31.0` - HTTP 请求库
- `requests-ntlm>=1.2.0` - NTLM 认证
- `python-dateutil>=2.8.2` - 日期处理
- `openai>=1.0.0` - OpenAI API（可选，用于 AI 分析）
- `anthropic>=0.18.0` - Anthropic API（可选，用于 AI 分析）

### 4. 配置威胁情报 API（可选）

如需使用威胁情报功能，请配置环境变量：

```bash
# VirusTotal API
export VIRUSTOTAL_API_KEY="your_api_key_here"

# AbuseIPDB API
export ABUSEIPDB_API_KEY="your_api_key_here"
```

详见 [THREAT_INTEL_GUIDE.md](THREAT_INTEL_GUIDE.md)

### 5. 配置 AI 分析（可选）

如需使用 AI 驱动分析功能，请配置：

```bash
# OpenAI API
export OPENAI_API_KEY="your_api_key_here"

# Anthropic Claude API
export ANTHROPIC_API_KEY="your_api_key_here"
```

详见 [AI_ANALYSIS_GUIDE.md](AI_ANALYSIS_GUIDE.md)

### 6. 配置目标主机

**Linux 主机准备:**
```bash
# 确保 SSH 服务已启动
sudo systemctl start sshd

# 或者配置 SSH 密钥认证
ssh-copy-id user@target-host
```

**Windows 主机准备:**
```powershell
# 启用 WinRM
Enable-PSRemoting -Force

# 配置防火墙规则
netsh advfirewall firewall add rule name="WinRM HTTP" dir=in action=allow protocol=TCP localport=5985

# 设置 WinRM 服务为自动启动
Set-Service WinRM -StartupType Automatic
Start-Service WinRM
```

## 使用方法

### ⚡ 快速开始（最简单）

**连接 Linux 主机（自动检测 OS）:**
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password "your_password"
```

**连接 Windows 主机（需指定协议）:**
```bash
python src/main.py \
  --host 192.168.1.200 \
  --username Administrator \
  --password "your_password" \
  --protocol winrm
```

**更多使用示例**，请参考：
- [QUICKSTART.md](QUICKSTART.md) - 5 分钟快速上手
- [HOW_TO_RUN.md](HOW_TO_RUN.md) - 详细运行说明
- [USAGE_EXAMPLES.md](USAGE_EXAMPLES.md) - 各种场景的使用示例

### 基本用法

**Linux 主机检查（带威胁描述）:**
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password "your_password" \
  --threat-desc "发现可疑进程占用高CPU，怀疑挖矿木马"
```

**Windows 主机检查:**
```bash
python src/main.py \
  --host 192.168.1.200 \
  --username Administrator \
  --password "your_password" \
  --protocol winrm \
  --threat-desc "发现可疑计划任务"
```

**使用 SSH 密钥认证（推荐）:**
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --key-file ~/.ssh/id_rsa
```

**自定义配置文件:**
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password "your_password" \
  --config config/custom_config.json \
  --output reports/custom_report.md
```

### 高级用法

#### 1. 集成威胁情报查询

配置 API 密钥后，工具会自动：
- 查询可疑文件哈希的 VirusTotal 信誉
- 检查外部连接 IP 的 AbuseIPDB 威胁评分
- 在报告中显示威胁情报结果

```bash
# 设置 API 密钥
export VIRUSTOTAL_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"

# 正常运行，自动集成威胁情报
python src/main.py --host 192.168.1.100 --username root --password "pass"
```

#### 2. 启用 AI 驱动分析

配置 AI API 后，工具会自动：
- 使用 GPT-4 或 Claude 分析安全事件
- 生成智能化的威胁评估报告
- 提供定制化的应急响应建议

```bash
# 设置 OpenAI API
export OPENAI_API_KEY="your_key"

# 或使用 Anthropic Claude
export ANTHROPIC_API_KEY="your_key"

# 运行时自动启用 AI 分析
python src/main.py --host 192.168.1.100 --username root --password "pass"
```

#### 3. 使用 MCP Server 模式

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
      "args": ["C:/Users/24767/Desktop/mcp-irt/mcp_server.py"]
    }
  }
}
```

然后在 Claude Desktop 中直接对话执行应急响应任务。详见 [AI_ANALYSIS_GUIDE.md](AI_ANALYSIS_GUIDE.md)

### 命令行参数

| 参数 | 必需 | 说明 |
|------|------|------|
| `--host` | 是 | 目标主机地址 |
| `--username` | 是 | 登录用户名 |
| `--password` | 条件 | 登录密码（或使用 --key-file） |
| `--key-file` | 条件 | SSH 私钥文件路径 |
| `--os-type` | 否 | 操作系统类型（linux/windows），**默认自动检测** |
| `--protocol` | 否 | 连接协议（ssh/winrm），默认根据OS自动选择 |
| `--port` | 否 | 连接端口（SSH默认22，WinRM默认5985） |
| `--threat-desc` | 否 | 威胁描述，**默认为"常规安全检查"** |
| `--config` | 否 | 配置文件路径（默认 config/config.json） |
| `--output` | 否 | 报告输出路径（默认自动生成） |

### 应急响应工作流

工具会按照预定义的工作流自动执行检查：

**Linux 工作流:**
1. 检查异常进程（高CPU、可疑路径、无签名）
2. 检查网络连接（监听端口、异常连接）
3. 检查计划任务（cron、at、systemd timer）
4. 检查日志（登录失败、sudo、异常时段）

**Windows 工作流:**
1. 检查异常进程（高CPU、未签名、可疑路径）
2. 检查网络连接（监听端口、异常连接）
3. 检查计划任务（Task Scheduler、启动项）
4. 检查日志（登录失败、用户创建、特权使用）

## 检查项说明

### Linux 检查项

1. **进程检查** (`check_processes.sh`)
   - 高 CPU/内存占用进程
   - 从临时目录运行的进程
   - 网络监听进程
   - 隐藏进程（进程 ID 不连续）
   - 无对应二进制文件的进程

2. **网络检查** (`check_network.sh`)
   - 监听端口扫描
   - 已建立的连接
   - 可疑端口检测（常见后门端口：4444, 5555, 6666 等）
   - 反向 Shell 特征识别
   - 防火墙规则检查
   - 异常外部连接（非标准端口）

3. **计划任务检查** (`check_cron.sh`)
   - 系统和用户 crontab
   - at 任务
   - systemd timer 单元
   - 最近修改的计划任务
   - 可疑的任务命令（下载、反向连接等）

4. **日志检查** (`check_logs.sh`)
   - SSH 登录失败/成功记录
   - root 用户活动追踪
   - sudo 命令执行历史
   - 用户添加/删除事件
   - 暴力破解迹象识别
   - 异常时段登录（深夜、凌晨）

5. **持久化机制检测** (`check_persistence.sh`)
   - Rootkit 检测（chkrootkit/rkhunter）
   - 启动脚本分析（init.d, rc.local）
   - 系统服务异常检查
   - LD_PRELOAD 劫持检测
   - PAM 后门检测

6. **后门签名扫描** (`check_backdoor_signatures.sh`)
   - 已知 Web Shell 特征
   - 常见后门工具签名
   - 可疑文件内容扫描

7. **系统完整性验证** (`check_system_integrity.sh`)
   - 关键系统文件哈希校验
   - 二进制文件篡改检测
   - 配置文件完整性验证

8. **用户安全分析** (`check_user_security.sh`)
   - 异常用户账户（UID 0、无 Shell 用户）
   - sudo 权限配置审查
   - SSH 密钥授权检查
   - 用户组成员关系分析

9. **进程内存转储** (`dump_process_memory.sh`)
   - 可疑进程的内存取证
   - 用于深度分析和威胁溯源

### Windows 检查项

1. **进程检查** (`check_processes.ps1`)
   - 高 CPU/内存占用进程
   - 未签名进程
   - 从临时目录运行的进程（Temp, AppData）
   - PowerShell/CMD 进程
   - 隐藏窗口进程
   - 无父进程的孤立进程

2. **网络检查** (`check_network.ps1`)
   - 监听端口扫描
   - 已建立的连接
   - 可疑端口检测
   - 防火墙规则检查
   - Hosts 文件篡改检测
   - 网络共享配置检查
   - 异常 DNS 配置

3. **计划任务检查** (`check_tasks.ps1`)
   - Task Scheduler 任务枚举
   - 包含可疑命令的任务（PowerShell、下载工具）
   - 从临时目录执行的任务
   - SYSTEM 权限任务
   - 注册表启动项（Run, RunOnce）
   - 启动文件夹内容
   - 服务配置异常检查

4. **日志检查** (`check_logs.ps1`)
   - 登录失败/成功（EventID 4625/4624）
   - 账户锁定事件（EventID 4740）
   - 新用户创建（EventID 4720）
   - 用户组变更（EventID 4732）
   - 特权使用记录（EventID 4672）
   - PowerShell 执行日志（EventID 4104）
   - Windows Defender 检测记录
   - RDP 连接记录

## 响应处置

### 终止可疑进程

**Linux:**
```bash
# 通过工具自动识别或手动执行
./scripts/linux/kill_process.sh <PID>
```

**Windows:**
```powershell
# 通过工具自动识别或手动执行
powershell -File scripts\windows\kill_process.ps1 -PID <PID>
```

### 阻断可疑IP

**Linux:**
```bash
# 使用 iptables 阻断
./scripts/linux/block_ip.sh <IP地址>
```

**Windows:**
```powershell
# 使用防火墙规则阻断
powershell -File scripts\windows\block_ip.ps1 -IPAddress <IP地址>
```

## 报告示例

生成的报告包含以下内容：

```markdown
# 应急响应报告

**生成时间**: 2025-12-15 14:30:22
**目标主机**: 192.168.1.100
**操作系统**: linux

## 威胁描述
发现可疑进程占用高CPU，怀疑挖矿木马

## 执行摘要
- 总步骤数: 4
- 成功: 4
- 失败: 0

## 执行详情
### 步骤 1: check_processes
- **状态**: ✅ 成功
- **时间**: 2025-12-15T14:30:25
- **发现**: ⚠️ 发现高危进程

**输出摘要**:
```
PID: 1234
进程名: xmrig
路径: /tmp/xmrig
CPU: 95%
内存: 2.1 GB
```

### 步骤 2: check_network
- **状态**: ✅ 成功
- **时间**: 2025-12-15T14:30:28
- **发现**: ⚠️ 发现可疑网络连接

**威胁情报查询结果**:
- IP: 198.51.100.123
- AbuseIPDB 威胁评分: 85/100
- 报告次数: 142
- 分类: 挖矿、恶意软件

...

## 威胁情报分析

### 可疑文件
- **文件**: /tmp/xmrig
- **SHA256**: a1b2c3d4...
- **VirusTotal 检测**: 45/70 引擎标记为恶意
- **分类**: Trojan.CoinMiner

### 可疑 IP
- **IP**: 198.51.100.123
- **AbuseIPDB 评分**: 85/100
- **已知用途**: 挖矿池、C2 服务器
- **建议**: 立即封禁

## AI 分析结果

**威胁评估**:
基于收集的数据，系统检测到典型的加密货币挖矿木马感染特征：
1. 高 CPU 占用进程运行于临时目录
2. 连接到已知的挖矿池 IP 地址
3. 进程名称与常见挖矿工具一致

**威胁等级**: 🔴 高危

**建议措施**:
1. 立即终止进程 PID 1234
2. 封禁 IP 198.51.100.123
3. 检查持久化机制（cron、启动项）
4. 扫描其他主机是否存在相同威胁
5. 修改所有用户密码
6. 审查 SSH 日志，排查入侵途径

## 发现的问题
### 可疑进程
- PID 1234: /tmp/xmrig (CPU 95%)

### 可疑网络连接
- 连接到可疑IP: 198.51.100.123:3333 (挖矿池)

## 建议措施
- ✅ 立即终止可疑进程并分析其来源
- ✅ 阻断可疑IP地址的网络访问
- ✅ 检查系统启动项和持久化机制
- ⚠️ 全面排查其他主机
```

完整的报告示例可以在 `reports/` 目录中查看。

## 自定义配置

编辑 `config/config.json` 来自定义工作流：

```json
{
  "workflow": {
    "linux": [
      "check_processes",
      "check_network",
      "check_cron",
      "check_logs",
      "check_persistence",
      "check_user_security"
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
      "check_processes": "scripts/linux/check_processes.sh",
      "check_network": "scripts/linux/check_network.sh",
      "check_cron": "scripts/linux/check_cron.sh",
      "check_logs": "scripts/linux/check_logs.sh",
      "check_persistence": "scripts/linux/check_persistence.sh",
      "check_docker": "scripts/linux/check_docker.sh"
    },
    "windows": {
      "check_processes": "scripts/windows/check_processes.ps1",
      "check_network": "scripts/windows/check_network.ps1",
      "check_tasks": "scripts/windows/check_tasks.ps1",
      "check_logs": "scripts/windows/check_logs.ps1"
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

### 添加自定义检查脚本

1. 在 `scripts/linux/` 或 `scripts/windows/` 目录创建脚本
2. 在 `config/config.json` 的 `scripts` 节中注册
3. 将脚本名称添加到 `workflow` 数组中

示例：添加 Docker 容器检查
```bash
# 创建脚本
touch scripts/linux/check_docker.sh
chmod +x scripts/linux/check_docker.sh

# 编辑 config/config.json，添加到 workflow 和 scripts
```

## 典型应用场景

### 1. 挖矿木马检测
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password "pass" \
  --threat-desc "服务器CPU占用率异常，疑似挖矿"
```

**检测特征**:
- 高 CPU 占用进程
- 连接到挖矿池 IP（端口 3333, 8080）
- 进程名包含 xmrig, minerd, cpuminer 等

### 2. 暴力破解响应
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password "pass" \
  --threat-desc "检测到大量SSH登录失败"
```

**检测内容**:
- SSH 认证失败日志
- 异常来源 IP
- 账户锁定事件
- 自动查询 IP 威胁情报

### 3. Web Shell 排查
```bash
python src/main.py \
  --host 192.168.1.200 \
  --username webadmin \
  --password "pass" \
  --threat-desc "网站目录发现可疑PHP文件"
```

**检测重点**:
- Web 目录异常文件
- 可疑进程（php, perl, python）
- 异常网络连接
- 文件完整性校验

### 4. 勒索软件响应
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password "pass" \
  --threat-desc "文件被加密，疑似勒索软件"
```

**响应流程**:
- 识别加密进程
- 检查勒索软件签名
- 分析持久化机制
- 生成取证报告

### 5. 内网横向移动检测
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password "pass" \
  --threat-desc "发现异常的内网连接"
```

**检测内容**:
- SMB/RDP 连接
- 异常端口扫描
- 凭据窃取痕迹
- 远程执行工具

## 文档导航

- **[QUICKSTART.md](QUICKSTART.md)** - 5 分钟快速上手指南
- **[HOW_TO_RUN.md](HOW_TO_RUN.md)** - 详细运行说明和工作流程
- **[USAGE_EXAMPLES.md](USAGE_EXAMPLES.md)** - 各种威胁场景的使用示例
- **[THREAT_INTEL_GUIDE.md](THREAT_INTEL_GUIDE.md)** - 威胁情报 API 配置和使用
- **[AI_ANALYSIS_GUIDE.md](AI_ANALYSIS_GUIDE.md)** - AI 分析功能配置和 MCP Server 使用
- **[ADVANCED_PERSISTENCE_DETECTION.md](ADVANCED_PERSISTENCE_DETECTION.md)** - 高级持久化机制检测指南
- **[ENHANCED_FEATURES_V2.md](ENHANCED_FEATURES_V2.md)** - 增强功能和高级特性文档
- **[CHANGELOG.md](CHANGELOG.md)** - 版本历史和更新日志
- **[WHATS_NEW.md](WHATS_NEW.md)** - 最新功能和改进

## 安全注意事项

1. **权限要求**: 某些检查需要管理员/root 权限
   - Linux: 建议使用具有 sudo 权限的账户
   - Windows: 需要 Administrator 账户或具有相应权限的用户

2. **密码安全**: 避免在命令行中直接传递密码
   - 优先使用 SSH 密钥认证（Linux）
   - 使用环境变量存储凭据
   - 避免在日志中记录密码

3. **网络安全**: 确保连接通道安全
   - 使用 VPN 或跳板机连接远程主机
   - 确保 SSH/WinRM 使用加密传输
   - 限制工具的网络访问范围

4. **取证保护**: 操作前确保已备份关键数据
   - 工具会修改系统状态（终止进程、封禁 IP）
   - 建议在非生产环境先测试
   - 保存所有操作日志和报告

5. **响应审慎**: 终止进程和阻断 IP 前请仔细确认
   - 可能影响业务正常运行
   - 建议先生成报告，分析后再执行响应动作
   - 对关键系统建议人工复核

6. **API 密钥管理**: 妥善保管威胁情报和 AI API 密钥
   - 使用环境变量，不要硬编码
   - 定期轮换 API 密钥
   - 限制 API 密钥权限

7. **合规性**: 确保操作符合法律法规
   - 获得目标系统所有者明确授权
   - 遵守数据保护和隐私法规
   - 记录所有操作审计日志

## 故障排除

### 连接失败

**问题**: 无法连接到目标主机

**解决方案**:
- 检查目标主机网络连通性: `ping <host>`
- 检查 SSH/WinRM 服务是否运行
  ```bash
  # Linux
  sudo systemctl status sshd
  
  # Windows
  Get-Service WinRM
  ```
- 验证用户名和密码是否正确
- 检查防火墙规则是否允许连接
- 验证端口是否正确（SSH 默认 22，WinRM 默认 5985/5986）

### 权限不足

**问题**: 某些命令执行失败，提示权限不足

**解决方案**:
- Linux: 使用具有 sudo 权限的用户或 root 用户
- Windows: 使用 Administrator 账户
- 检查目标主机的 sudo 配置（Linux）
- 验证 WinRM 的执行策略（Windows）

### 脚本执行失败

**问题**: 脚本无法执行或返回错误

**解决方案**:
- Linux: 检查脚本是否有执行权限
  ```bash
  chmod +x scripts/linux/*.sh
  ```
- Windows: 检查 PowerShell 执行策略
  ```powershell
  Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```
- 检查脚本语法错误
- 查看详细错误日志: `logs/` 目录

### 威胁情报查询失败

**问题**: VirusTotal 或 AbuseIPDB 查询失败

**解决方案**:
- 验证 API 密钥是否正确配置
  ```bash
  echo $VIRUSTOTAL_API_KEY
  echo $ABUSEIPDB_API_KEY
  ```
- 检查 API 配额是否用尽
- 验证网络连接，确保能访问外部 API
- 检查 API 密钥权限和有效期

### AI 分析不工作

**问题**: AI 分析功能未启用或返回错误

**解决方案**:
- 验证 AI API 密钥配置
  ```bash
  echo $OPENAI_API_KEY
  echo $ANTHROPIC_API_KEY
  ```
- 检查 config.json 中的 AI 配置
- 验证网络连接到 AI 服务
- 检查 API 余额和速率限制

### 依赖包安装失败

**问题**: pip install 失败或缺少依赖

**解决方案**:
- 升级 pip: `python -m pip install --upgrade pip`
- 使用国内镜像（中国大陆用户）:
  ```bash
  pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
  ```
- 单独安装失败的包
- 检查 Python 版本是否 >= 3.7

### WinRM 连接问题

**问题**: 无法连接到 Windows 主机

**解决方案**:
- 在目标 Windows 主机上启用 WinRM:
  ```powershell
  Enable-PSRemoting -Force
  Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*"
  ```
- 检查防火墙规则:
  ```powershell
  netsh advfirewall firewall show rule name="Windows Remote Management (HTTP-In)"
  ```
- 使用 HTTPS (端口 5986) 而不是 HTTP (端口 5985)
- 验证 NTLM 认证是否启用

## 开发和扩展

### 添加自定义检查脚本

1. 创建脚本文件
   ```bash
   # Linux
   touch scripts/linux/check_custom.sh
   chmod +x scripts/linux/check_custom.sh
   
   # Windows
   New-Item scripts\windows\check_custom.ps1
   ```

2. 编写脚本内容（参考现有脚本格式）
   ```bash
   #!/bin/bash
   # check_custom.sh - 自定义检查脚本
   
   echo "=== 开始自定义检查 ==="
   # 你的检查逻辑
   echo "检查完成"
   ```

3. 在 `config/config.json` 中注册
   ```json
   {
     "scripts": {
       "linux": {
         "check_custom": "scripts/linux/check_custom.sh"
       }
     },
     "workflow": {
       "linux": [
         "check_processes",
         "check_custom"
       ]
     }
   }
   ```

### 自定义检测逻辑

在 `src/executor.py` 中扩展威胁检测逻辑：

```python
class IRTExecutor:
    def _analyze_and_respond(self, step_name, output):
        """自定义分析逻辑"""
        if "YOUR_PATTERN" in output:
            # 执行响应动作
            self._execute_response_action(...)
```

### 集成自定义威胁情报源

在 `src/threat_intel.py` 中添加新的威胁情报源：

```python
class CustomThreatIntel:
    def query_custom_api(self, indicator):
        """查询自定义威胁情报 API"""
        # 实现查询逻辑
        pass
```

### 扩展响应动作

在 `src/response_engine.py` 中添加新的响应动作：

```python
class ResponseEngine:
    def custom_action(self, params):
        """自定义响应动作"""
        # 实现响应逻辑
        pass
```

### 贡献代码

欢迎通过以下方式贡献：
1. Fork 项目仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

## 技术架构

### 系统架构图

```
┌─────────────────────────────────────────────────────────┐
│                    CLI / MCP Interface                  │
│                      (main.py)                          │
└────────────────────┬────────────────────────────────────┘
                     │
        ┌────────────┴───────────┐
        │                        │
┌───────▼────────┐      ┌────────▼────────┐
│   Connector    │      │   Config Mgr    │
│  (SSH/WinRM)   │      │  (config.py)    │
└───────┬────────┘      └─────────────────┘
        │
┌───────▼──────────────────────────────────────────┐
│              Executor Engine                     │
│           (executor.py)                          │
│  ┌──────────────────────────────────────────┐   │
│  │  Script Runner → Result Collector        │   │
│  └──────────────┬───────────────────────────┘   │
└─────────────────┼───────────────────────────────┘
                  │
     ┌────────────┼────────────┐
     │            │            │
┌────▼───┐  ┌────▼────┐  ┌───▼─────┐
│Threat  │  │Behavior │  │  AI     │
│Intel   │  │Analyzer │  │Analyzer │
└────┬───┘  └────┬────┘  └───┬─────┘
     │           │            │
     └───────────┼────────────┘
                 │
        ┌────────▼──────────┐
        │  Response Engine  │
        │ (response_engine) │
        └────────┬──────────┘
                 │
        ┌────────▼──────────┐
        │  Report Generator │
        │   (reporter.py)   │
        └───────────────────┘
```

### 数据流

1. **输入**: CLI 参数或 MCP 请求
2. **连接**: SSH/WinRM 建立到目标主机
3. **执行**: 按工作流顺序执行检查脚本
4. **收集**: 汇总所有脚本输出
5. **分析**:
   - 威胁情报查询（VirusTotal, AbuseIPDB）
   - 行为模式分析
   - AI 驱动分析（可选）
6. **响应**: 执行自动化响应动作（可选）
7. **报告**: 生成 Markdown 格式报告

## 性能优化建议

1. **并行执行**: 对于多台主机，使用多线程/多进程并行检查
2. **缓存结果**: 缓存威胁情报查询结果，避免重复查询
3. **脚本优化**: 优化 Shell/PowerShell 脚本，减少执行时间
4. **按需加载**: 仅在需要时启用威胁情报和 AI 分析
5. **日志级别**: 生产环境降低日志级别，提高性能

## 许可证

本项目仅用于授权的安全测试和应急响应场景。

**使用限制**:
- 仅供合法安全测试和应急响应
- 必须获得目标系统所有者明确授权
- 禁止用于未经授权的渗透测试或攻击
- 使用者对工具使用后果承担全部责任

## 免责声明

本工具仅供合法的安全测试和应急响应使用。使用者需确保：

1. **授权要求**: 已获得目标系统所有者的明确授权
2. **法律合规**: 遵守当地法律法规和网络安全法
3. **责任承担**: 对使用本工具造成的任何后果负责
4. **教育用途**: 可用于网络安全教育和培训
5. **禁止滥用**: 禁止将本工具用于非法目的

**开发者声明**:
- 本工具仅作为安全防护和应急响应的辅助工具
- 开发者不对工具的误用或滥用承担任何责任
- 使用本工具即表示同意本免责声明

## 更新日志

### v1.0.0 (2025-12-15)
**初始版本发布**
- ✅ 支持 Linux 和 Windows 主机
- ✅ 实现基础应急响应工作流
- ✅ 自动化报告生成（Markdown 格式）
- ✅ SSH 和 WinRM 远程连接支持
- ✅ 进程、网络、计划任务、日志检查
- ✅ 可疑进程终止和 IP 封禁功能

**高级功能**:
- ✅ 威胁情报集成（VirusTotal, AbuseIPDB）
- ✅ AI 驱动分析（OpenAI GPT-4, Anthropic Claude）
- ✅ 行为模式分析引擎
- ✅ 高级持久化机制检测
- ✅ 进程内存取证转储
- ✅ MCP Server 支持（Claude Desktop 集成）
- ✅ 自动化响应引擎
- ✅ 威胁检测和评分系统

**脚本清单**:
- 11 个 Linux 安全检查脚本
- 6 个 Windows 安全检查脚本
- 完整的工作流配置系统

**文档**:
- 完整的中文文档
- 快速上手指南
- 详细使用示例
- 威胁情报和 AI 分析指南

详见 [CHANGELOG.md](CHANGELOG.md) 查看完整更新历史。
