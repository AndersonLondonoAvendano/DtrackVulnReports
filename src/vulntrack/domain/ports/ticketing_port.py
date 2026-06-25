from typing import Any, Protocol


class TicketingPort(Protocol):
    async def create_ticket(self, **fields: Any) -> str: ...

    async def update_ticket(self, ticket_id: str, **fields: Any) -> None: ...
