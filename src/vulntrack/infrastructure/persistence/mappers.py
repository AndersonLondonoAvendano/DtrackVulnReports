"""Funciones de conversión entre ORM models y domain entities."""
from __future__ import annotations

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot, SnapshotSource
from vulntrack.domain.entities.project import Project
from vulntrack.domain.entities.remediation import RemediationPlan, RemediationTask, TaskStatus
from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.infrastructure.persistence.orm_models import (
    FindingORM,
    KevEntryORM,
    MetricSnapshotORM,
    ProjectORM,
    RemediationPlanORM,
    RemediationTaskORM,
)


def orm_to_project(row: ProjectORM) -> Project:
    return Project(
        uuid=row.uuid,
        name=row.name,
        version=row.version,
        description=row.description,
        last_bom_import=row.last_bom_import,
        last_synced_at=row.last_synced_at,
    )


def project_to_orm(p: Project) -> ProjectORM:
    return ProjectORM(
        uuid=p.uuid,
        name=p.name,
        version=p.version,
        description=p.description,
        last_bom_import=p.last_bom_import,
        last_synced_at=p.last_synced_at,
    )


def orm_to_snapshot(row: MetricSnapshotORM) -> MetricSnapshot:
    return MetricSnapshot(
        id=row.id,
        project_uuid=row.project_uuid,
        snapshot_date=row.snapshot_date,
        critical=row.critical,
        high=row.high,
        medium=row.medium,
        low=row.low,
        unassigned=row.unassigned,
        total=row.total,
        risk_score=row.risk_score,
        source=SnapshotSource(row.source),
    )


def snapshot_to_orm(s: MetricSnapshot) -> MetricSnapshotORM:
    return MetricSnapshotORM(
        id=s.id if s.id != 0 else None,  # type: ignore[arg-type]
        project_uuid=s.project_uuid,
        snapshot_date=s.snapshot_date,
        critical=s.critical,
        high=s.high,
        medium=s.medium,
        low=s.low,
        unassigned=s.unassigned,
        total=s.total,
        risk_score=s.risk_score,
        source=s.source.value,
    )


def orm_to_finding(row: FindingORM) -> Finding:
    return Finding(
        id=row.id,
        project_uuid=row.project_uuid,
        dt_finding_uuid=row.dt_finding_uuid,
        component_name=row.component_name,
        component_version=row.component_version,
        component_group=row.component_group,
        vuln_id=row.vuln_id,
        vuln_source=row.vuln_source,
        severity=Severity(row.severity),
        cvss_v3_base_score=row.cvss_v3_base_score,
        epss_score=row.epss_score,
        epss_percentile=row.epss_percentile,
        attributed_on=row.attributed_on,
        suppressed=row.suppressed,
        last_synced_at=row.last_synced_at,
        cve_id=row.cve_id,
    )


def orm_to_kev(row: KevEntryORM) -> KevEntry:
    return KevEntry(
        cve_id=row.cve_id,
        vendor_project=row.vendor_project,
        product=row.product,
        vulnerability_name=row.vulnerability_name,
        date_added=row.date_added,
        short_description=row.short_description,
        required_action=row.required_action,
        due_date=row.due_date,
        notes=row.notes,
    )


def orm_to_plan(row: RemediationPlanORM) -> RemediationPlan:
    return RemediationPlan(
        id=row.id,
        project_uuid=row.project_uuid,
        name=row.name,
        description=row.description,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def orm_to_task(row: RemediationTaskORM) -> RemediationTask:
    return RemediationTask(
        id=row.id,
        plan_id=row.plan_id,
        finding_id=row.finding_id,
        title=row.title,
        description=row.description,
        assignee=row.assignee,
        status=TaskStatus(row.status),
        priority_band=PriorityBand(row.priority_band),
        recommended_action=row.recommended_action,
        target_date=row.target_date,
        completed_at=row.completed_at,
        notes=row.notes,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )
