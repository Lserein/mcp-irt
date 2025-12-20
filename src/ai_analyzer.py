"""
AI分析模块
支持两种模式：
1. API模式：通过API key调用AI服务（OpenAI、Claude等）
2. MCP模式：通过MCP server调用本地AI
"""

import json
import os
import subprocess
from typing import Dict, List, Optional
from datetime import datetime


class AIAnalyzer:
    """AI分析器"""

    def __init__(self, config: Dict, whitelist: Optional[Dict] = None):
        """
        初始化AI分析器

        Args:
            config: 配置字典
            whitelist: 白名单配置（可选）
        """
        self.config = config
        self.ai_config = config.get('ai_analysis', {})
        self.enabled = self.ai_config.get('enabled', False)
        self.mode = self.ai_config.get('mode', 'api')  # 'api' or 'mcp'

        # API模式配置
        self.api_provider = self.ai_config.get('api_provider', 'openai')  # openai, claude, etc
        self.api_key = self.ai_config.get('api_key', '')
        self.api_model = self.ai_config.get('api_model', 'gpt-4')
        self.api_endpoint = self.ai_config.get('api_endpoint', '')

        # MCP模式配置
        self.mcp_server_path = self.ai_config.get('mcp_server_path', 'mcp_server.py')

        # 白名单配置
        self.whitelist = whitelist or {}

        self.analysis_results = []

    def is_enabled(self) -> bool:
        """检查AI分析是否启用"""
        return self.enabled

    def analyze_script_output(
        self,
        script_name: str,
        script_output: str,
        os_type: str,
        context: Optional[Dict] = None
    ) -> Dict:
        """
        分析脚本输出

        Args:
            script_name: 脚本名称
            script_output: 脚本输出内容
            os_type: 操作系统类型
            context: 额外的上下文信息

        Returns:
            AI分析结果
        """
        if not self.enabled:
            return {'enabled': False}

        if not script_output or len(script_output.strip()) < 10:
            return {
                'enabled': True,
                'analyzed': False,
                'reason': 'Script output is empty or too short'
            }

        # 构建分析提示词
        prompt = self._build_analysis_prompt(script_name, script_output, os_type, context)

        # 根据模式调用不同的AI服务
        if self.mode == 'api':
            result = self._analyze_via_api(prompt)
        elif self.mode == 'mcp':
            result = self._analyze_via_mcp(prompt)
        else:
            result = {
                'error': f'Unknown AI mode: {self.mode}',
                'analyzed': False
            }

        # 添加元数据
        result['script_name'] = script_name
        result['timestamp'] = datetime.now().isoformat()
        result['mode'] = self.mode

        self.analysis_results.append(result)

        return result

    def _build_analysis_prompt(
        self,
        script_name: str,
        script_output: str,
        os_type: str,
        context: Optional[Dict]
    ) -> str:
        """构建AI分析提示词"""

        # 限制输出长度（避免token过多）
        max_output_length = 8000
        if len(script_output) > max_output_length:
            script_output = script_output[:max_output_length] + "\n...(输出已截断)"

        # 构建白名单说明
        whitelist_info = ""
        if self.whitelist:
            whitelist_ips = self.whitelist.get('ips', [])
            whitelist_processes = self.whitelist.get('processes', [])
            whitelist_paths = self.whitelist.get('paths', [])

            if whitelist_ips or whitelist_processes or whitelist_paths:
                whitelist_info = "\n**白名单配置（以下内容应排除，不视为威胁）**:\n"
                if whitelist_ips:
                    whitelist_info += f"- 白名单IP地址: {', '.join(whitelist_ips)}\n"
                if whitelist_processes:
                    whitelist_info += f"- IRT工具进程: {', '.join(whitelist_processes[:5])}等\n"
                if whitelist_paths:
                    whitelist_info += f"- IRT工具路径: {', '.join(whitelist_paths)}\n"

        prompt = f"""你是一个专业的Linux安全应急响应专家。请分析以下脚本的输出结果，识别潜在的安全威胁。

**脚本信息**:
- 脚本名称: {script_name}
- 操作系统: {os_type}
- 执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{whitelist_info}
**脚本输出**:
```
{script_output}
```

**分析要求**:
1. **威胁识别**: 识别输出中的所有可疑内容和安全威胁
2. **严重程度评估**: 对每个威胁评估严重程度（Critical/High/Medium/Low）
3. **威胁分类**: 对威胁进行分类（后门、权限提升、持久化、数据窃取等）
4. **具体指标**: 提取具体的威胁指标（IP地址、进程PID、文件路径、用户名等）
5. **处置建议**: 针对每个威胁给出具体的处置建议

**请以JSON格式返回分析结果**:
{{
  "threats": [
    {{
      "description": "威胁描述",
      "severity": "Critical/High/Medium/Low",
      "category": "威胁类型",
      "indicators": ["具体指标1", "具体指标2"],
      "evidence": "输出中的证据",
      "recommendation": "处置建议"
    }}
  ],
  "overall_risk_score": 0-100,
  "summary": "总体分析摘要",
  "immediate_actions": ["需要立即执行的动作"],
  "false_positives": ["可能的误报项"]
}}

**注意**:
- 仔细分析输出中标记为 [!] 或 "可疑" 的内容
- 关注UID=0的用户、可疑进程、异常端口、后门特征等
- 区分正常行为和恶意行为
- **重要**: 排除白名单中的IP地址、IRT工具进程（如irt_check_processes等）和IRT工具路径（如/tmp/irt_*.sh等），这些是应急响应工具自身的活动，不是威胁
- 如果输出显示正常，threats数组可以为空
"""

        return prompt

    def _analyze_via_api(self, prompt: str) -> Dict:
        """通过API调用AI分析"""
        try:
            if self.api_provider == 'openai':
                return self._call_openai_api(prompt)
            elif self.api_provider == 'claude':
                return self._call_claude_api(prompt)
            elif self.api_provider == 'qwen':
                return self._call_qwen_api(prompt)
            elif self.api_provider == 'custom':
                return self._call_custom_api(prompt)
            else:
                return {
                    'error': f'Unsupported API provider: {self.api_provider}',
                    'analyzed': False
                }
        except Exception as e:
            import traceback
            return {
                'error': f'API analysis failed: {str(e)}',
                'analyzed': False,
                'exception_type': type(e).__name__,
                'traceback': traceback.format_exc()
            }

    def _call_openai_api(self, prompt: str) -> Dict:
        """调用OpenAI API"""
        try:
            import openai

            openai.api_key = self.api_key

            if self.api_endpoint:
                openai.api_base = self.api_endpoint

            response = openai.ChatCompletion.create(
                model=self.api_model,
                messages=[
                    {
                        "role": "system",
                        "content": "你是一个专业的安全应急响应专家，擅长分析系统日志和脚本输出，识别安全威胁。"
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000
            )

            content = response.choices[0].message.content.strip()

            # 尝试解析JSON
            result = self._parse_ai_response(content)
            result['analyzed'] = True
            result['raw_response'] = content

            return result

        except ImportError:
            return {
                'error': 'OpenAI library not installed. Run: pip install openai',
                'analyzed': False
            }
        except Exception as e:
            return {
                'error': f'OpenAI API error: {str(e)}',
                'analyzed': False
            }

    def _call_claude_api(self, prompt: str) -> Dict:
        """调用Claude API"""
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key)

            message = client.messages.create(
                model=self.api_model,
                max_tokens=2000,
                temperature=0.3,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            content = message.content[0].text.strip()

            # 尝试解析JSON
            result = self._parse_ai_response(content)
            result['analyzed'] = True
            result['raw_response'] = content

            return result

        except ImportError:
            return {
                'error': 'Anthropic library not installed. Run: pip install anthropic',
                'analyzed': False
            }
        except Exception as e:
            return {
                'error': f'Claude API error: {str(e)}',
                'analyzed': False
            }

    def _call_qwen_api(self, prompt: str) -> Dict:
        """调用千问（Qwen）API"""
        try:
            import requests

            # 千问API使用阿里云DashScope服务
            # 默认endpoint
            endpoint = self.api_endpoint or 'https://dashscope.aliyuncs.com/api/v1/services/aigc/text-generation/generation'

            # 默认模型
            model = self.api_model or 'qwen-turbo'

            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }

            # 千问API请求格式
            data = {
                'model': model,
                'input': {
                    'messages': [
                        {
                            'role': 'system',
                            'content': '你是一个专业的安全应急响应专家，擅长分析系统日志和脚本输出，识别安全威胁。'
                        },
                        {
                            'role': 'user',
                            'content': prompt
                        }
                    ]
                },
                'parameters': {
                    'result_format': 'message',
                    'temperature': 0.3,
                    'max_tokens': 2000
                }
            }

            response = requests.post(
                endpoint,
                headers=headers,
                json=data,
                timeout=60
            )

            response.raise_for_status()
            response_data = response.json()

            # 检查API响应状态
            if response_data.get('code'):
                error_code = response_data.get('code')
                error_msg = response_data.get('message', 'Unknown error')
                return {
                    'error': f'Qwen API error [{error_code}]: {error_msg}',
                    'analyzed': False
                }

            # 提取响应内容
            output = response_data.get('output', {})
            choices = output.get('choices', [])

            if not choices:
                return {
                    'error': 'Qwen API returned empty response',
                    'analyzed': False
                }

            # 获取助手的回复
            content = choices[0].get('message', {}).get('content', '').strip()

            if not content:
                return {
                    'error': 'Qwen API returned empty content',
                    'analyzed': False
                }

            # 尝试解析JSON
            result = self._parse_ai_response(content)
            result['analyzed'] = True
            result['raw_response'] = content
            result['usage'] = response_data.get('usage', {})

            return result

        except ImportError:
            return {
                'error': 'requests library not installed. Run: pip install requests',
                'analyzed': False
            }
        except requests.exceptions.RequestException as e:
            return {
                'error': f'Qwen API request error: {str(e)}',
                'analyzed': False,
                'exception_type': type(e).__name__
            }
        except Exception as e:
            import traceback
            return {
                'error': f'Qwen API error: {str(e)}',
                'analyzed': False,
                'exception_type': type(e).__name__,
                'traceback': traceback.format_exc()
            }

    def _call_custom_api(self, prompt: str) -> Dict:
        """调用自定义API"""
        try:
            import requests

            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }

            data = {
                'model': self.api_model,
                'messages': [
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'temperature': 0.3,
                'max_tokens': 2000
            }

            response = requests.post(
                self.api_endpoint,
                headers=headers,
                json=data,
                timeout=60
            )

            response.raise_for_status()
            response_data = response.json()

            # 根据不同的API格式提取内容
            content = self._extract_content_from_response(response_data)

            # 尝试解析JSON
            result = self._parse_ai_response(content)
            result['analyzed'] = True
            result['raw_response'] = content

            return result

        except Exception as e:
            return {
                'error': f'Custom API error: {str(e)}',
                'analyzed': False
            }

    def _analyze_via_mcp(self, prompt: str) -> Dict:
        """通过MCP Server调用AI分析"""
        try:
            # 检查MCP server文件是否存在
            if not os.path.exists(self.mcp_server_path):
                return {
                    'error': f'MCP server not found: {self.mcp_server_path}',
                    'analyzed': False
                }

            # 准备输入数据
            input_data = {
                'prompt': prompt,
                'max_tokens': 2000,
                'temperature': 0.3
            }

            # 调用MCP server
            result = subprocess.run(
                ['python', self.mcp_server_path, 'analyze'],
                input=json.dumps(input_data),
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                return {
                    'error': f'MCP server error: {result.stderr}',
                    'analyzed': False
                }

            # 解析MCP server的输出
            response_data = json.loads(result.stdout)

            if 'error' in response_data:
                return {
                    'error': response_data['error'],
                    'analyzed': False
                }

            content = response_data.get('response', '')

            # 尝试解析JSON
            parsed_result = self._parse_ai_response(content)
            parsed_result['analyzed'] = True
            parsed_result['raw_response'] = content
            parsed_result['mcp_metadata'] = response_data.get('metadata', {})

            return parsed_result

        except subprocess.TimeoutExpired:
            return {
                'error': 'MCP server timeout (120s)',
                'analyzed': False
            }
        except Exception as e:
            import traceback
            return {
                'error': f'MCP analysis error: {str(e)}',
                'analyzed': False,
                'exception_type': type(e).__name__,
                'traceback': traceback.format_exc()
            }

    def _parse_ai_response(self, content: str) -> Dict:
        """解析AI响应，提取JSON"""
        try:
            # 尝试直接解析
            return json.loads(content)
        except json.JSONDecodeError:
            # 尝试提取JSON块
            import re

            # 查找```json ... ```块
            json_match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except:
                    pass

            # 查找{}块
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(0))
                except:
                    pass

            # 解析失败，返回原始文本
            return {
                'threats': [],
                'overall_risk_score': 0,
                'summary': content,
                'parse_error': 'Failed to parse JSON from AI response'
            }

    def _extract_content_from_response(self, response_data: Dict) -> str:
        """从不同格式的API响应中提取内容"""
        # OpenAI格式
        if 'choices' in response_data:
            return response_data['choices'][0]['message']['content']

        # Claude格式
        if 'content' in response_data:
            if isinstance(response_data['content'], list):
                return response_data['content'][0]['text']
            return response_data['content']

        # 通用格式
        if 'response' in response_data:
            return response_data['response']

        if 'text' in response_data:
            return response_data['text']

        return str(response_data)

    def get_comprehensive_analysis(self) -> Dict:
        """获取所有脚本的综合AI分析"""
        if not self.analysis_results:
            return {
                'total_analyzed': 0,
                'threats': [],
                'overall_risk_score': 0
            }

        # 汇总所有威胁
        all_threats = []
        total_risk_score = 0
        analyzed_count = 0

        for result in self.analysis_results:
            if result.get('analyzed'):
                analyzed_count += 1
                threats = result.get('threats', [])
                all_threats.extend(threats)
                total_risk_score += result.get('overall_risk_score', 0)

        # 计算平均风险分数
        avg_risk_score = total_risk_score / analyzed_count if analyzed_count > 0 else 0

        # 按严重程度分类
        critical_threats = [t for t in all_threats if t.get('severity') == 'Critical']
        high_threats = [t for t in all_threats if t.get('severity') == 'High']
        medium_threats = [t for t in all_threats if t.get('severity') == 'Medium']
        low_threats = [t for t in all_threats if t.get('severity') == 'Low']

        return {
            'total_analyzed': analyzed_count,
            'threats': all_threats,
            'threats_by_severity': {
                'critical': len(critical_threats),
                'high': len(high_threats),
                'medium': len(medium_threats),
                'low': len(low_threats)
            },
            'overall_risk_score': round(avg_risk_score, 2),
            'critical_threats': critical_threats,
            'high_threats': high_threats,
            'recommendations': self._generate_recommendations(all_threats)
        }

    def _generate_recommendations(self, threats: List[Dict]) -> List[str]:
        """生成综合建议"""
        recommendations = []

        # 从所有威胁中收集建议
        for threat in threats:
            rec = threat.get('recommendation')
            if rec and rec not in recommendations:
                recommendations.append(rec)

        return recommendations[:10]  # 返回最多10条建议
