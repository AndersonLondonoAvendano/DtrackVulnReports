from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vulntrack.domain.services.treatment_transitions import ACTIVE_TREATMENT_STATES
from vulntrack.infrastructure.persistence.database import Base

_ACTIVE_STATES_SQL = ",".join(f"'{s}'" for s in sorted(ACTIVE_TREATMENT_STATES))


class ProjectORM(Base):
    __tablename__ = "projects"

    uuid: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(100))
    description: Mapped[str | None] = mapped_column(Text)
    last_bom_import: Mapped[datetime | None] = mapped_column(DateTime)
    last_synced_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    snapshots: Mapped[list[MetricSnapshotORM]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    findings: Mapped[list[FindingORM]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    remediation_plans: Mapped[list[RemediationPlanORM]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    treatments: Mapped[list[VulnerabilityTreatmentORM]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class MetricSnapshotORM(Base):
    __tablename__ = "metric_snapshots"
    __table_args__ = (
        Index("ix_metric_snapshots_project_date", "project_uuid", "snapshot_date"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_uuid: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.uuid", ondelete="CASCADE"), nullable=False
    )
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False)
    critical: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    medium: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    low: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unassigned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)

    project: Mapped[ProjectORM] = relationship(back_populates="snapshots")


class FindingORM(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("project_uuid", "dt_finding_uuid", name="uq_findings_project_dt_uuid"),
        Index("ix_findings_project_severity", "project_uuid", "severity"),
        Index("ix_findings_vuln_id", "vuln_id"),
        Index("ix_findings_attributed_on", "attributed_on"),
        Index("ix_findings_cve_id", "cve_id"),
        # D1 (iter4-design.md): identidad = proyecto + CVE canónico (o vuln_id
        # si no hay CVE) + componente + versión. `COALESCE` normaliza tanto la
        # ausencia de CVE como la ausencia de versión, igual que
        # `domain.services.vuln_identity.identity_key`.
        Index(
            "uq_findings_identity",
            "project_uuid",
            text("COALESCE(cve_id, vuln_id)"),
            "component_name",
            text("COALESCE(component_version, '')"),
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_uuid: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.uuid", ondelete="CASCADE"), nullable=False
    )
    dt_finding_uuid: Mapped[str] = mapped_column(String(36), nullable=False)
    component_name: Mapped[str] = mapped_column(String(255), nullable=False)
    component_version: Mapped[str | None] = mapped_column(String(100))
    component_group: Mapped[str | None] = mapped_column(String(255))
    vuln_id: Mapped[str] = mapped_column(String(100), nullable=False)
    vuln_source: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(30), nullable=True)
    cvss_v3_base_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    attributed_on: Mapped[datetime | None] = mapped_column(DateTime)
    suppressed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_synced_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    # Ciclo de vida (Bloque B, iter4-design.md §2): ACTIVA mientras el sync
    # sigue confirmando la vulnerabilidad; RESUELTA cuando deja de aparecer.
    estado_ciclo_vida: Mapped[str] = mapped_column(
        String(20), nullable=False, default="ACTIVA"
    )
    primera_deteccion_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ultima_vista_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resuelta_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    es_reincidente: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reaparicion_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ultima_reaparicion_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    project: Mapped[ProjectORM] = relationship(back_populates="findings")


class KevEntryORM(Base):
    __tablename__ = "kev_entries"

    cve_id: Mapped[str] = mapped_column(String(30), primary_key=True)
    vendor_project: Mapped[str] = mapped_column(String(255), nullable=False)
    product: Mapped[str] = mapped_column(String(255), nullable=False)
    vulnerability_name: Mapped[str] = mapped_column(String(500), nullable=False)
    date_added: Mapped[date] = mapped_column(Date, nullable=False)
    short_description: Mapped[str] = mapped_column(Text, nullable=False)
    required_action: Mapped[str] = mapped_column(Text, nullable=False)
    due_date: Mapped[date | None] = mapped_column(Date)
    notes: Mapped[str | None] = mapped_column(Text)
    catalog_updated_at: Mapped[datetime | None] = mapped_column(DateTime)


class RemediationPlanORM(Base):
    __tablename__ = "remediation_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_uuid: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.uuid", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    sprint_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("sprints.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    project: Mapped[ProjectORM] = relationship(back_populates="remediation_plans")
    sprint: Mapped[SprintORM | None] = relationship(back_populates="plans")
    treatments: Mapped[list[VulnerabilityTreatmentORM]] = relationship(back_populates="plan")

    # NOTA (iteración 4, retiro del sistema legado de tareas): la tabla física
    # `remediation_tasks` (~872 filas históricas) NO se elimina -- queda
    # huérfana, sin clase ORM que la mapee. El plan de remediación materializa
    # sus ítems como `VulnerabilityTreatmentORM` (ver `treatments` arriba).


class AppSettingsORM(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    sync_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    kev_stale_days: Mapped[int] = mapped_column(Integer, nullable=False, default=7)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_kev_update_at: Mapped[datetime | None] = mapped_column(DateTime)
    w_cvss_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.30)
    w_epss_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.40)
    w_kev_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.30)
    kev_minimum_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.75)
    epss_high_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.40)
    cvss_high_threshold: Mapped[float] = mapped_column(Float, nullable=False, default=7.0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )


class SprintORM(Base):
    __tablename__ = "sprints"
    __table_args__ = (
        CheckConstraint("fecha_fin > fecha_inicio", name="ck_sprints_fecha_fin_after_inicio"),
        Index("ix_sprints_anio_trimestre", "anio", "trimestre"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    nombre: Mapped[str] = mapped_column(String(255), nullable=False)
    anio: Mapped[int] = mapped_column(Integer, nullable=False)
    trimestre: Mapped[int] = mapped_column(Integer, nullable=False)
    fecha_inicio: Mapped[date] = mapped_column(Date, nullable=False)
    fecha_fin: Mapped[date] = mapped_column(Date, nullable=False)
    estado: Mapped[str] = mapped_column(String(20), nullable=False, default="PLANEADO")
    # D1: nullable, preparado para integración futura (Jira/Azure DevOps).
    external_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    origen: Mapped[str] = mapped_column(String(20), nullable=False, default="MANUAL")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    plans: Mapped[list[RemediationPlanORM]] = relationship(back_populates="sprint")
    treatments: Mapped[list[VulnerabilityTreatmentORM]] = relationship(back_populates="sprint")


class VulnerabilityTreatmentORM(Base):
    __tablename__ = "vulnerability_treatments"
    __table_args__ = (
        # D1/D2 (iteración 4): anti-duplicación a nivel de BD — un solo
        # tratamiento activo (y con `activo_en_plan`) por identidad completa
        # (proyecto, vuln_key, componente, versión). Ambos kwargs se declaran
        # para portabilidad SQLite (hoy) / PostgreSQL (ADR-006).
        Index(
            "uq_treatment_active_project_vuln",
            "project_uuid",
            "vuln_key",
            "component_name",
            text("COALESCE(component_version, '')"),
            unique=True,
            sqlite_where=text(f"estado IN ({_ACTIVE_STATES_SQL}) AND activo_en_plan = 1"),
            postgresql_where=text(f"estado IN ({_ACTIVE_STATES_SQL}) AND activo_en_plan = 1"),
        ),
        Index("ix_treatments_project_estado", "project_uuid", "estado"),
        Index("ix_treatments_sprint", "sprint_id"),
        Index("ix_treatments_vuln_key", "vuln_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_uuid: Mapped[str] = mapped_column(
        String(36), ForeignKey("projects.uuid", ondelete="CASCADE"), nullable=False
    )
    # CVE si existe, si no vuln_id (GHSA) — clave de deduplicación (D2).
    vuln_key: Mapped[str] = mapped_column(String(100), nullable=False)
    cve_id: Mapped[str | None] = mapped_column(String(30), nullable=True)
    finding_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    plan_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("remediation_plans.id", ondelete="SET NULL"), nullable=True
    )
    sprint_id: Mapped[int] = mapped_column(Integer, ForeignKey("sprints.id"), nullable=False)
    responsable: Mapped[str | None] = mapped_column(String(255), nullable=True)
    estado: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDIENTE")
    priority_band: Mapped[str] = mapped_column(String(20), nullable=False)
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    fecha_objetivo: Mapped[date | None] = mapped_column(Date, nullable=True)
    fecha_cierre: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    notas: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Obligatorio (a nivel de aplicación) si estado es POSPUESTA/DESCARTADA.
    motivo: Mapped[str | None] = mapped_column(Text, nullable=True)
    recurrence_flag: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_recurrence_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    component_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    component_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    # "MANUAL" (usuario) vs "AUSENCIA_DT" (D3: finalizado automáticamente
    # porque el finding dejó de aparecer en un sync). None mientras no está
    # en un estado terminal.
    finalizacion_subtipo: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # D4: si es False, el tratamiento fue desvinculado de su plan (delete
    # híbrido, T-E011) pero su historial se conserva para métricas; ya no
    # bloquea la identidad en el índice único de arriba.
    activo_en_plan: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    project: Mapped[ProjectORM] = relationship(back_populates="treatments")
    sprint: Mapped[SprintORM] = relationship(back_populates="treatments")
    plan: Mapped[RemediationPlanORM | None] = relationship(back_populates="treatments")
    history: Mapped[list[TreatmentStatusHistoryORM]] = relationship(
        back_populates="treatment", cascade="all, delete-orphan"
    )


class TreatmentStatusHistoryORM(Base):
    __tablename__ = "treatment_status_history"
    __table_args__ = (
        Index("ix_treatment_history_treatment", "treatment_id"),
        Index("ix_treatment_history_sprint", "sprint_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    treatment_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("vulnerability_treatments.id", ondelete="CASCADE"), nullable=False
    )
    from_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_status: Mapped[str] = mapped_column(String(20), nullable=False)
    sprint_id: Mapped[int] = mapped_column(Integer, ForeignKey("sprints.id"), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    treatment: Mapped[VulnerabilityTreatmentORM] = relationship(back_populates="history")
