"""模型客户端：真实 Ollama 与离线 Fake 两种实现。

## 为什么先写 FakeClient

agent 层的行为（循环、终止、降级、预算）与模型输出质量是两件正交的事。
把两者耦合在一起测，会导致：换一个模型测试就红，而红的原因可能是模型
措辞变了、而不是循环逻辑错了。

FakeClient 让循环逻辑可以离线、确定性地测——给定一串预设响应，
循环应当走出确定的轨迹。这是 P5「一切可回放」在测试层的落地。

## 协议

两边都只需实现一个方法：

    chat(messages, tools) -> ChatResponse

`ChatResponse` 只承载三种形态：文本、工具调用、或两者皆有。不引入
更复杂的抽象——Ollama 原生返回就是 messages + tool_calls。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

__all__ = [
    "ToolCall",
    "ChatResponse",
    "LLMError",
    "FakeClient",
    "OllamaClient",
]


class LLMError(RuntimeError):
    """模型层故障。调用方必须捕获并降级，不得让程序崩掉。"""


@dataclass
class ToolCall:
    name: str
    arguments: dict

    def signature(self) -> str:
        """调用签名，用于判重复调用。

        参数必须排序后序列化——dict 顺序不同不等于是不同的调用，
        否则「同一次调用换个键序」会被当成新进展，重复检测就失效了。
        """
        return f"{self.name}:{json.dumps(self.arguments, sort_keys=True, ensure_ascii=False)}"


@dataclass
class ChatResponse:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)


# ===========================================================================
# 离线 Fake
# ===========================================================================


class FakeClient:
    """按预设脚本回放响应的假客户端。

    用法：

        fake = FakeClient([
            ChatResponse(tool_calls=[ToolCall("list_rules", {})]),
            ChatResponse(tool_calls=[ToolCall("submit_findings", {...})]),
        ])

    脚本用完后返回一个空的 ChatResponse（无文本、无工具调用），
    用于测试「模型空转」的降级路径。
    """

    def __init__(self, responses: list[ChatResponse]) -> None:
        self._script = list(responses)
        self.calls: list[list[dict]] = []

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> ChatResponse:
        self.calls.append(messages)
        if self._script:
            return self._script.pop(0)
        return ChatResponse()


# ===========================================================================
# 真实 Ollama
# ===========================================================================


class OllamaClient:
    """Ollama 的 /api/chat 客户端。

    ## 为什么用 urllib 而不是 requests

    项目声明「零运行时依赖」。多引一个包换来的只是几行代码的便利，
    却给部署增加了版本约束。urllib 够用。

    ## 关于工具支持

    Ollama 的 tools 依赖模型的 template 里含 `{{ .Tools }}`。不支持 tools
    的模型不会报错，只是静默忽略——因此调用方必须做**启动自检**：
    发一个强制调工具的 prompt，看回来有没有 tool_calls。没有就降级。
    这个自检不能靠「模型声称支持」来判断。
    """

    def __init__(
        self,
        model: str,
        base_url: str = "http://localhost:11434",
        timeout: float = 120.0,
        temperature: float = 0.0,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.temperature = temperature

    def chat(self, messages: list[dict], tools: list[dict] | None = None) -> ChatResponse:
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        if tools:
            payload["tools"] = tools

        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise LLMError(f"无法连接 Ollama（{self.base_url}）：{exc}") from exc
        except json.JSONDecodeError as exc:
            raise LLMError(f"Ollama 返回非 JSON：{exc}") from exc

        message = body.get("message") or {}
        calls: list[ToolCall] = []
        for raw in message.get("tool_calls") or []:
            fn = raw.get("function") or {}
            args = fn.get("arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            calls.append(ToolCall(name=str(fn.get("name", "")), arguments=args or {}))

        return ChatResponse(content=str(message.get("content") or ""), tool_calls=calls)

    def probe_tools(self) -> bool:
        """启动自检：该模型是否真的支持工具调用。

        ## 为什么必须实测

        「模型声称支持 tools」与「template 里真的有 .Tools 占位」是两回事。
        后者才决定 Ollama 会不会把工具描述塞进 prompt。判断错了的后果是
        agent 永远拿不到 tool_calls，然后静默降级成一个笨命令行——而用户
        看到的是「AI 什么都没做」。
        """
        messages = [
            {"role": "user", "content": "调用 probe_ping 工具，参数 name 填 test。不要说话，只调工具。"}
        ]
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "probe_ping",
                    "description": "自检用工具，回显 name",
                    "parameters": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                        "required": ["name"],
                    },
                },
            }
        ]
        try:
            resp = self.chat(messages, tools)
        except LLMError:
            return False
        return any(c.name == "probe_ping" for c in resp.tool_calls)
