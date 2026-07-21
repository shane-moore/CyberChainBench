"""Core agent runtimes used by the benchmark."""

try:
    from .curator import (
        BenchmarkCurator,
        Curator,
        build_curator,
    )
except (ImportError, ModuleNotFoundError):
    BenchmarkCurator = None
    Curator = None
    build_curator = None

try:
    from .live_scrape_agent import LiveScrapeAgent
except (ImportError, ModuleNotFoundError):
    LiveScrapeAgent = None

__all__ = [
    "Curator",
    "BenchmarkCurator",
    "build_curator",
    "LiveScrapeAgent",
]

try:
    from . import task_agent as _task_agent
except ModuleNotFoundError:
    pass
else:
    AgentResponse = _task_agent.AgentResponse
    BaseAgent = _task_agent.BaseAgent
    CLI_FAMILY_SPECS = _task_agent.CLI_FAMILY_SPECS
    CliCodingAgent = _task_agent.CliCodingAgent
    MockAgent = _task_agent.MockAgent
    TaskType = _task_agent.TaskType
    __all__.extend(
        [
            "AgentResponse",
            "BaseAgent",
            "TaskType",
            "CliCodingAgent",
            "CLI_FAMILY_SPECS",
            "MockAgent",
        ]
    )
