"""
AgentGuard Proxy Package
========================
Public surface area for the proxy layer:
  - AgentGuardProxy  : the FastAPI + FastMCP gateway class
  - PolicyEngine     : static/dynamic rule evaluator
  - RedactionPipeline: PII scrubbing layer
  - PolicyDecision   : typed result from the engine
"""

from proxy.engine import PolicyDecision, PolicyEngine
from proxy.gateway import AgentGuardProxy, create_app
from proxy.redaction import RedactionPipeline

__all__ = [
    "AgentGuardProxy",
    "create_app",
    "PolicyDecision",
    "PolicyEngine",
    "RedactionPipeline",
]
