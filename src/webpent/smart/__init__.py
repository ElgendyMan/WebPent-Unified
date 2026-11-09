"""VIP Smart Autonomous Bug Hunter — smart enhancement modules.

GOVERNANCE: All modules are advisory and augmentative only.
They NEVER bypass or override existing causal evaluators or governance gates.
"""
from webpent.smart.integration import VIPSmartHunter
from webpent.smart.memory_engine import MemoryEntry, SmartMemory
from webpent.smart.prioritizer import PrioritizedFinding, SmartPrioritizer
from webpent.smart.reporter import SmartReporter
from webpent.smart.strategy_engine import DetectionPlan, SmartStrategyEngine

__all__ = [
    "SmartMemory",
    "MemoryEntry",
    "SmartStrategyEngine",
    "DetectionPlan",
    "SmartPrioritizer",
    "PrioritizedFinding",
    "SmartReporter",
    "VIPSmartHunter",
]
