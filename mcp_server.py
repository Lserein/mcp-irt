#!/usr/bin/env python3
"""
MCP-IRT Server - 多模式应急响应服务器
支持 MCP 协议和 Socket 远程连接

使用方法:
1. MCP 模式（Claude Desktop 集成）:
   python mcp_server.py serve

2. Socket 模式（多客户端远程访问）:
   python mcp_server.py socket --host 0.0.0.0 --port 8888

3. 命令行分析模式:
   python mcp_server.py analyze < input.json

配置文件 (~/.config/Claude/claude_desktop_config.json):
{
  "mcpServers": {
    "mcp-irt-analyzer": {
      "command": "python",
      "args": ["C:/Users/24767/Desktop/mcp-irt/mcp_server.py", "serve"]
    }
  }
}

Socket 客户端示例:
    import socket
    import json

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('localhost', 8888))

    # 发送命令
    command = {
        'action': 'execute_irt',
        'host': '192.168.1.100',
        'username': 'root',
        'password': 'password'
    }
    sock.sendall(json.dumps(command).encode('utf-8') + b'\n')

    # 接收响应
    response = b''
    while True:
        data = sock.recv(4096)
        if not data:
            break
        response += data
        if b'\n' in data:
            break
    print(json.loads(response.decode('utf-8')))
    sock.close()
"""

import sys
import json
import os
import socket
import threading
import queue
import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/mcp_server.log'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger('MCPServer')


class MCPAnalyzer:
    """MCP AI分析服务器"""

    def __init__(self):
        """初始化MCP分析器"""
        self.tools = {
            "analyze_security_output": {
                "description": "分析安全脚本输出，识别威胁",
                "parameters": {
                    "script_name": "脚本名称",
                    "output": "脚本输出内容",
                    "os_type": "操作系统类型"
                }
            },
            "analyze_threat": {
                "description": "深度分析特定威胁",
                "parameters": {
                    "threat_type": "威胁类型",
                    "indicators": "威胁指标",
                    "context": "上下文信息"
                }
            },
            "generate_response_plan": {
                "description": "生成应急响应计划",
                "parameters": {
                    "threats": "威胁列表",
                    "system_info": "系统信息"
                }
            }
        }

    def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理MCP请求

        Args:
            request: MCP请求

        Returns:
            MCP响应
        """
        try:
            method = request.get('method', '')

            if method == 'tools/list':
                return self._list_tools()
            elif method == 'tools/call':
                return self._call_tool(request)
            else:
                return {
                    'error': f'Unknown method: {method}'
                }

        except Exception as e:
            return {
                'error': str(e)
            }

    def _list_tools(self) -> Dict[str, Any]:
        """列出可用工具"""
        return {
            'tools': [
                {
                    'name': name,
                    'description': tool['description'],
                    'inputSchema': {
                        'type': 'object',
                        'properties': tool['parameters']
                    }
                }
                for name, tool in self.tools.items()
            ]
        }

    def _call_tool(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """调用工具"""
        params = request.get('params', {})
        tool_name = params.get('name', '')
        arguments = params.get('arguments', {})

        if tool_name == 'analyze_security_output':
            return self._analyze_security_output(arguments)
        elif tool_name == 'analyze_threat':
            return self._analyze_threat(arguments)
        elif tool_name == 'generate_response_plan':
            return self._generate_response_plan(arguments)
        else:
            return {
                'error': f'Unknown tool: {tool_name}'
            }

    def _analyze_security_output(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """分析安全脚本输出"""
        script_name = args.get('script_name', 'unknown')
        output = args.get('output', '')
        os_type = args.get('os_type', 'linux')

        analysis_prompt = f"""请分析以下{os_type}系统安全检查脚本的输出，识别安全威胁。

脚本名称: {script_name}

输出内容:
{output[:6000]}

请以JSON格式返回分析结果，包括:
1. 识别的威胁列表（包括描述、严重程度、指标）
2. 整体风险评分（0-100）
3. 处置建议
"""

        return {
            'content': [
                {
                    'type': 'text',
                    'text': analysis_prompt
                }
            ]
        }

    def _analyze_threat(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """深度分析威胁"""
        threat_type = args.get('threat_type', '')
        indicators = args.get('indicators', [])
        context = args.get('context', {})

        analysis_prompt = f"""请深度分析以下安全威胁:

威胁类型: {threat_type}
威胁指标: {json.dumps(indicators, indent=2, ensure_ascii=False)}
上下文信息: {json.dumps(context, indent=2, ensure_ascii=False)}

请提供:
1. 威胁的工作原理
2. 攻击者可能的目的
3. 影响范围评估
4. 详细的清除步骤
5. 加固建议
"""

        return {
            'content': [
                {
                    'type': 'text',
                    'text': analysis_prompt
                }
            ]
        }

    def _generate_response_plan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """生成应急响应计划"""
        threats = args.get('threats', [])
        system_info = args.get('system_info', {})

        plan_prompt = f"""基于以下威胁信息，生成详细的应急响应计划:

检测到的威胁:
{json.dumps(threats, indent=2, ensure_ascii=False)}

系统信息:
{json.dumps(system_info, indent=2, ensure_ascii=False)}

请生成:
1. 应急响应时间线
2. 每个威胁的具体处置步骤
3. 优先级排序
4. 所需工具和命令
5. 回滚方案
6. 后续加固建议
"""

        return {
            'content': [
                {
                    'type': 'text',
                    'text': plan_prompt
                }
            ]
        }

    def serve(self):
        """
        启动MCP服务器模式
        读取stdin的JSON-RPC请求，返回响应
        """
        logger.info("MCP-IRT AI Analyzer Server started in MCP mode")
        logger.info("Waiting for JSON-RPC requests from Claude Desktop...")

        try:
            for line in sys.stdin:
                try:
                    request = json.loads(line.strip())
                    response = self.handle_request(request)
                    print(json.dumps(response))
                    sys.stdout.flush()
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error: {e}")
                    error_response = {
                        'error': {
                            'code': -32700,
                            'message': f'Parse error: {str(e)}'
                        }
                    }
                    print(json.dumps(error_response))
                    sys.stdout.flush()
                except Exception as e:
                    logger.error(f"Request handling error: {e}")
                    error_response = {
                        'error': {
                            'code': -32603,
                            'message': str(e)
                        }
                    }
                    print(json.dumps(error_response))
                    sys.stdout.flush()
        except KeyboardInterrupt:
            logger.info("MCP server stopped by user")
        except Exception as e:
            logger.error(f"Fatal error in MCP server: {e}")
            raise


class SocketIRTServer:
    """基于 Socket 的应急响应服务器"""

    def __init__(self, host: str = '0.0.0.0', port: int = 8888, max_clients: int = 10):
        """
        初始化 Socket 服务器

        Args:
            host: 监听地址
            port: 监听端口
            max_clients: 最大客户端连接数
        """
        self.host = host
        self.port = port
        self.max_clients = max_clients
        self.server_socket: Optional[socket.socket] = None
        self.clients: Dict[str, socket.socket] = {}
        self.client_threads: Dict[str, threading.Thread] = {}
        self.running = False
        self.lock = threading.Lock()

        # 确保日志目录存在
        os.makedirs('logs', exist_ok=True)

    def start(self):
        """启动服务器"""
        try:
            # 创建 TCP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # 设置 socket 选项，允许地址重用
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 绑定地址和端口
            self.server_socket.bind((self.host, self.port))
            # 开始监听，设置最大连接队列
            self.server_socket.listen(self.max_clients)
            self.running = True

            logger.info(f"Socket IRT Server started on {self.host}:{self.port}")
            logger.info(f"Max clients: {self.max_clients}")
            logger.info("Waiting for client connections...")

            # 接受客户端连接
            while self.running:
                try:
                    # 设置超时，以便可以响应 stop 信号
                    self.server_socket.settimeout(1.0)
                    client_socket, client_address = self.server_socket.accept()

                    # 为每个客户端创建独立线程
                    client_id = f"{client_address[0]}:{client_address[1]}"

                    with self.lock:
                        if len(self.clients) >= self.max_clients:
                            logger.warning(f"Max clients reached, rejecting {client_id}")
                            error_msg = {
                                'status': 'error',
                                'message': 'Server is full, max clients reached'
                            }
                            client_socket.sendall(json.dumps(error_msg).encode('utf-8') + b'\n')
                            client_socket.close()
                            continue

                        self.clients[client_id] = client_socket

                    logger.info(f"New client connected: {client_id}")

                    # 启动客户端处理线程
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_id),
                        daemon=True
                    )
                    client_thread.start()

                    with self.lock:
                        self.client_threads[client_id] = client_thread

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")

        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        except Exception as e:
            logger.error(f"Fatal server error: {e}")
        finally:
            self.stop()

    def _handle_client(self, client_socket: socket.socket, client_id: str):
        """
        处理单个客户端连接

        Args:
            client_socket: 客户端 socket
            client_id: 客户端标识
        """
        try:
            # 发送欢迎消息
            welcome_msg = {
                'status': 'connected',
                'message': 'Welcome to MCP-IRT Socket Server',
                'client_id': client_id,
                'timestamp': datetime.now().isoformat()
            }
            self._send_message(client_socket, welcome_msg)

            # 接收客户端数据
            buffer = b''
            while self.running:
                try:
                    # 接收数据
                    data = client_socket.recv(4096)

                    if not data:
                        # 客户端关闭连接
                        logger.info(f"Client {client_id} disconnected")
                        break

                    buffer += data

                    # 处理完整的消息（以换行符分隔）
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)

                        try:
                            # 解码为字符串
                            message_str = line.decode('utf-8').strip()
                            if not message_str:
                                continue

                            # 解析 JSON
                            message = json.loads(message_str)
                            logger.info(f"Received from {client_id}: {message.get('action', 'unknown')}")

                            # 处理消息
                            response = self._process_message(message, client_id, client_socket)

                            # 发送响应
                            self._send_message(client_socket, response)

                        except json.JSONDecodeError as e:
                            logger.error(f"JSON decode error from {client_id}: {e}")
                            error_response = {
                                'status': 'error',
                                'message': f'Invalid JSON: {str(e)}'
                            }
                            self._send_message(client_socket, error_response)
                        except Exception as e:
                            logger.error(f"Error processing message from {client_id}: {e}")
                            error_response = {
                                'status': 'error',
                                'message': str(e)
                            }
                            self._send_message(client_socket, error_response)

                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error reading from {client_id}: {e}")
                    break

        except Exception as e:
            logger.error(f"Client handler error for {client_id}: {e}")
        finally:
            # 清理客户端连接
            self._cleanup_client(client_id, client_socket)

    def _send_message(self, client_socket: socket.socket, message: Dict[str, Any]):
        """
        发送消息给客户端

        Args:
            client_socket: 客户端 socket
            message: 消息字典
        """
        try:
            # 将消息转换为 JSON 字符串并编码为字节
            message_json = json.dumps(message, ensure_ascii=False)
            message_bytes = message_json.encode('utf-8') + b'\n'

            # 发送数据
            client_socket.sendall(message_bytes)
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            raise

    def _process_message(self, message: Dict[str, Any], client_id: str, client_socket: socket.socket) -> Dict[str, Any]:
        """
        处理客户端消息

        Args:
            message: 客户端消息
            client_id: 客户端标识
            client_socket: 客户端 socket

        Returns:
            响应消息
        """
        action = message.get('action', '')

        try:
            if action == 'ping':
                return {
                    'status': 'success',
                    'action': 'pong',
                    'timestamp': datetime.now().isoformat()
                }

            elif action == 'execute_irt':
                # 执行应急响应检查
                return self._execute_irt_check(message, client_id, client_socket)

            elif action == 'get_status':
                return {
                    'status': 'success',
                    'server_info': {
                        'connected_clients': len(self.clients),
                        'max_clients': self.max_clients,
                        'uptime': 'running'
                    }
                }

            elif action == 'disconnect':
                return {
                    'status': 'success',
                    'message': 'Disconnecting...'
                }

            else:
                return {
                    'status': 'error',
                    'message': f'Unknown action: {action}'
                }

        except Exception as e:
            logger.error(f"Error processing action '{action}': {e}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def _execute_irt_check(self, message: Dict[str, Any], client_id: str, client_socket: socket.socket) -> Dict[str, Any]:
        """
        执行应急响应检查（模拟）

        Args:
            message: 客户端消息
            client_id: 客户端标识
            client_socket: 客户端 socket

        Returns:
            执行结果
        """
        host = message.get('host')
        username = message.get('username')
        password = message.get('password')

        if not all([host, username, password]):
            return {
                'status': 'error',
                'message': 'Missing required parameters: host, username, password'
            }

        # 发送进度消息
        self._send_progress(client_socket, "开始连接到目标主机...", 10)
        time.sleep(0.5)

        self._send_progress(client_socket, f"正在连接 {host}...", 20)
        time.sleep(0.5)

        self._send_progress(client_socket, "执行进程检查...", 40)
        time.sleep(0.5)

        self._send_progress(client_socket, "执行网络检查...", 60)
        time.sleep(0.5)

        self._send_progress(client_socket, "执行日志分析...", 80)
        time.sleep(0.5)

        self._send_progress(client_socket, "生成报告...", 90)
        time.sleep(0.5)

        # 返回最终结果
        return {
            'status': 'success',
            'action': 'execute_irt',
            'host': host,
            'timestamp': datetime.now().isoformat(),
            'result': {
                'checks_completed': 4,
                'threats_found': 0,
                'report_path': f'reports/irt_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.md'
            },
            'progress': 100
        }

    def _send_progress(self, client_socket: socket.socket, message: str, progress: int):
        """
        发送进度消息

        Args:
            client_socket: 客户端 socket
            message: 进度消息
            progress: 进度百分比
        """
        progress_msg = {
            'status': 'progress',
            'message': message,
            'progress': progress,
            'timestamp': datetime.now().isoformat()
        }
        try:
            self._send_message(client_socket, progress_msg)
        except Exception as e:
            logger.error(f"Error sending progress: {e}")

    def _cleanup_client(self, client_id: str, client_socket: socket.socket):
        """
        清理客户端连接

        Args:
            client_id: 客户端标识
            client_socket: 客户端 socket
        """
        try:
            # 关闭 socket
            client_socket.close()
            logger.info(f"Client {client_id} connection closed")
        except Exception as e:
            logger.error(f"Error closing client socket: {e}")
        finally:
            # 从客户端列表中移除
            with self.lock:
                self.clients.pop(client_id, None)
                self.client_threads.pop(client_id, None)

    def stop(self):
        """停止服务器"""
        logger.info("Stopping server...")
        self.running = False

        # 关闭所有客户端连接
        with self.lock:
            for client_id, client_socket in list(self.clients.items()):
                try:
                    goodbye_msg = {
                        'status': 'server_shutdown',
                        'message': 'Server is shutting down'
                    }
                    self._send_message(client_socket, goodbye_msg)
                    client_socket.close()
                except Exception as e:
                    logger.error(f"Error closing client {client_id}: {e}")

            self.clients.clear()
            self.client_threads.clear()

        # 关闭服务器 socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                logger.error(f"Error closing server socket: {e}")

        logger.info("Server stopped")


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("用法: python mcp_server.py [serve|socket|analyze]")
        print("  serve   - 启动MCP服务器模式（用于Claude Desktop）")
        print("  socket  - 启动Socket服务器模式（支持多客户端远程连接）")
        print("          选项: --host <address> --port <port> --max-clients <num>")
        print("  analyze - 命令行分析模式（从stdin读取JSON）")
        print("\n示例:")
        print("  python mcp_server.py serve")
        print("  python mcp_server.py socket --host 0.0.0.0 --port 8888")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == 'serve':
        # MCP服务器模式
        analyzer = MCPAnalyzer()
        analyzer.serve()

    elif mode == 'socket':
        # Socket服务器模式
        import argparse
        parser = argparse.ArgumentParser(description='Socket IRT Server')
        parser.add_argument('mode', help='Server mode (socket)')
        parser.add_argument('--host', default='0.0.0.0', help='Server host (default: 0.0.0.0)')
        parser.add_argument('--port', type=int, default=8888, help='Server port (default: 8888)')
        parser.add_argument('--max-clients', type=int, default=10, help='Max clients (default: 10)')

        args = parser.parse_args()

        server = SocketIRTServer(host=args.host, port=args.port, max_clients=args.max_clients)
        server.start()

    elif mode == 'analyze':
        # 命令行分析模式
        analyzer = MCPAnalyzer()
        try:
            input_data = json.load(sys.stdin)
            # 这里可以调用实际的分析逻辑
            result = {
                'status': 'success',
                'message': 'Analysis completed',
                'data': input_data
            }
            print(json.dumps(result, ensure_ascii=False, indent=2))
        except Exception as e:
            error_result = {
                'status': 'error',
                'error': str(e)
            }
            print(json.dumps(error_result, ensure_ascii=False))
            sys.exit(1)

    else:
        print(f"未知模式: {mode}")
        print("可用模式: serve, socket, analyze")
        sys.exit(1)


if __name__ == '__main__':
    main()
