"""Reviewed adapters. All remote I/O uses an injected authorized transport."""

from .base import AdapterCapabilities, AdapterContext, Stimulus, TransportResponse
from .http import HTTPAgentAdapter
from .mcp import MCPAdapter
from .openai_compatible import OpenAICompatibleAdapter
from .trace import StructuredTraceAdapter

__all__ = [
    "AdapterCapabilities",
    "AdapterContext",
    "Stimulus",
    "TransportResponse",
    "HTTPAgentAdapter",
    "MCPAdapter",
    "OpenAICompatibleAdapter",
    "StructuredTraceAdapter",
]
