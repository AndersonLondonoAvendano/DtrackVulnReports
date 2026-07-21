from __future__ import annotations

from abc import ABC, abstractmethod


class AppSettingsRepository(ABC):
    @abstractmethod
    async def update(self, **fields: object) -> object: ...
