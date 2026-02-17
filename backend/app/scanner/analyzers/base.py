"""Base analyzer interface."""

from abc import ABC, abstractmethod

from ...models import Finding


class BaseAnalyzer(ABC):
    """Base class for code analyzers."""

    @abstractmethod
    def analyze(self, file_path: str, content: str, metadata: dict) -> list[Finding]:
        """Analyze a file and return findings."""
        ...

    @property
    @abstractmethod
    def supported_languages(self) -> list[str]:
        """Languages this analyzer supports."""
        ...
