class DomainError(Exception):
    pass


class ProjectNotFoundError(DomainError):
    def __init__(self, uuid: str) -> None:
        super().__init__(f"Project not found: {uuid}")
        self.uuid = uuid


class SnapshotNotAvailableError(DomainError):
    def __init__(self, project_uuid: str, context: str = "") -> None:
        msg = f"No snapshot available for project {project_uuid}"
        if context:
            msg += f" ({context})"
        super().__init__(msg)
        self.project_uuid = project_uuid
