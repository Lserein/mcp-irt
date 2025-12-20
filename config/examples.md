# MCP-IRT 使用示例

## Linux 主机示例

### 使用密码连接
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password 'your_password' \
  --os-type linux \
  --threat-desc "发现可疑进程占用高CPU"
```

### 使用SSH密钥连接
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username admin \
  --key-file ~/.ssh/id_rsa \
  --os-type linux \
  --threat-desc "检测到异常网络连接"
```

### 指定输出路径
```bash
python src/main.py \
  --host 192.168.1.100 \
  --username root \
  --password 'your_password' \
  --os-type linux \
  --output reports/incident_20251215.md
```

## Windows 主机示例

### 使用WinRM连接
```bash
python src/main.py \
  --host 192.168.1.200 \
  --username Administrator \
  --password 'your_password' \
  --os-type windows \
  --protocol winrm \
  --threat-desc "发现可疑计划任务"
```

### 指定非标准端口
```bash
python src/main.py \
  --host 192.168.1.200 \
  --port 5986 \
  --username Administrator \
  --password 'your_password' \
  --os-type windows \
  --protocol winrm
```

## 常见场景

### 场景1: 发现挖矿木马
```bash
python src/main.py \
  --host compromised-server.example.com \
  --username admin \
  --key-file ~/.ssh/id_rsa \
  --os-type linux \
  --threat-desc "CPU占用异常，怀疑挖矿木马"
```

### 场景2: 检测到暴力破解
```bash
python src/main.py \
  --host web-server.example.com \
  --username root \
  --password 'SecurePass123!' \
  --os-type linux \
  --threat-desc "auth.log显示大量登录失败"
```

### 场景3: 发现反向Shell
```bash
python src/main.py \
  --host app-server.example.com \
  --username sysadmin \
  --password 'Admin@2025' \
  --os-type linux \
  --threat-desc "监测到可疑外连 IP:port"
```

### 场景4: Windows勒索软件
```bash
python src/main.py \
  --host file-server.example.com \
  --username Administrator \
  --password 'WinAdmin2025!' \
  --os-type windows \
  --threat-desc "大量文件被加密，怀疑勒索软件"
```

## 自定义配置

你可以修改 `config/config.json` 来自定义检查流程：

```json
{
  "workflow": {
    "linux": [
      "check_processes",
      "check_network",
      "check_cron",
      "check_logs"
    ]
  }
}
```

添加自定义脚本：

```json
{
  "scripts": {
    "linux": {
      "check_docker": "scripts/linux/check_docker.sh",
      "check_webshell": "scripts/linux/check_webshell.sh"
    }
  },
  "workflow": {
    "linux": [
      "check_processes",
      "check_network",
      "check_docker",
      "check_webshell",
      "check_cron",
      "check_logs"
    ]
  }
}
```

## 响应动作示例

工具会自动识别可疑活动，你也可以手动执行响应动作：

### 终止可疑进程
编辑 `executor.py` 中的响应逻辑，或者直接SSH到目标主机执行：
```bash
./scripts/linux/kill_process.sh 12345
```

### 阻断可疑IP
```bash
./scripts/linux/block_ip.sh 198.51.100.123
```

## 查看报告

报告默认保存在 `reports/` 目录下：

```bash
cat reports/irt_report_20251215_143022.md
```

报告包含：
- 执行摘要
- 详细检查结果
- 发现的问题汇总
- 建议措施
