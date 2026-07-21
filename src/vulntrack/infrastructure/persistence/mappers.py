"""Funciones de conversión entre ORM models y domain entities."""
from __future__ import annotations

from vulntrack.domain.entities.finding import Finding, FindingLifecycleState
from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.entities.metric_snapshot import MetricSnapshot, SnapshotSource
from vulntrack.domain.entities.project import Project
from vulntrack.domain.entities.remediation import RemediationPlan
from vulntrack.domain.entities.sprint import Sprint, SprintStatus
from vulntrack.domain.entities.vulnerability_treatment import (
    TratamientoVulnerabilidad,
    TreatmentStatus,
    TreatmentStatusHistoryEntry,
)
from vulntrack.domain.value_objects.priority_score import PriorityBand
from vulntrack.domain.value_objects.severity import Severity
from vulntrack.infrastructure.persistence.orm_models import (
    FindingORM,
    KevEntryORM,
    MetricSnapshotORM,
    ProjectORM,
    RemediationPlanORM,
    SprintORM,
    TreatmentStatusHistoryORM,
    VulnerabilityTreatmentORM,
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
        estado_ciclo_vida=FindingLifecycleState(row.estado_ciclo_vida),
        primera_deteccion_at=row.primera_deteccion_at,
        ultima_vista_at=row.ultima_vista_at,
        resuelta_at=row.resuelta_at,
        es_reincidente=row.es_reincidente,
        reaparicion_count=row.reaparicion_count,
        ultima_reaparicion_at=row.ultima_reaparicion_at,
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
        sprint_id=row.sprint_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def orm_to_sprint(row: SprintORM) -> Sprint:
    return Sprint(
        id=row.id,
        nombre=row.nombre,
        anio=row.anio,
        trimestre=row.trimestre,
        fecha_inicio=row.fecha_inicio,
        fecha_fin=row.fecha_fin,
        estado=SprintStatus(row.estado),
        origen=row.origen,
        created_at=row.created_at,
        updated_at=row.updated_at,
        external_id=row.external_id,
    )


def orm_to_treatment(row: VulnerabilityTreatmentORM) -> TratamientoVulnerabilidad:
    return TratamientoVulnerabilidad(
        id=row.id,
        project_uuid=row.project_uuid,
        vuln_key=row.vuln_key,
        cve_id=row.cve_id,
        finding_id=row.finding_id,
        plan_id=row.plan_id,
        sprint_id=row.sprint_id,
        responsable=row.responsable,
        estado=TreatmentStatus(row.estado),
        priority_band=PriorityBand(row.priority_band),
        fecha_creacion=row.fecha_creacion,
        fecha_objetivo=row.fecha_objetivo,
        fecha_cierre=row.fecha_cierre,
        notas=row.notas,
        motivo=row.motivo,
        recurrence_flag=row.recurrence_flag,
        recurrence_count=row.recurrence_count,
        last_recurrence_at=row.last_recurrence_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        component_name=row.component_name,
        component_version=row.component_version,
        finalizacion_subtipo=row.finalizacion_subtipo,  # type: ignore[arg-type]
        activo_en_plan=row.activo_en_plan,
    )


def orm_to_history_entry(row: TreatmentStatusHistoryORM) -> TreatmentStatusHistoryEntry:
    return TreatmentStatusHistoryEntry(
        id=row.id,
        treatment_id=row.treatment_id,
        from_status=TreatmentStatus(row.from_status) if row.from_status else None,
        to_status=TreatmentStatus(row.to_status),
        sprint_id=row.sprint_id,
        changed_at=row.changed_at,
        note=row.note,
    )
