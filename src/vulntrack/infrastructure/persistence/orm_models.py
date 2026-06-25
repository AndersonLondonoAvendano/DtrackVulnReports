from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vulntrack.infrastructure.persistence.database import Base


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
        UniqueConstraint("dt_finding_uuid", name="uq_findings_dt_uuid"),
        Index("ix_findings_project_severity", "project_uuid", "severity"),
        Index("ix_findings_vuln_id", "vuln_id"),
        Index("ix_findings_attributed_on", "attributed_on"),
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
    cvss_v3_base_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    attributed_on: Mapped[datetime | None] = mapped_column(DateTime)
    suppressed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_synced_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    project: Mapped[ProjectORM] = relationship(back_populates="remediation_plans")
    tasks: Mapped[list[RemediationTaskORM]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )


class RemediationTaskORM(Base):
    __tablename__ = "remediation_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    plan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("remediation_plans.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("findings.id", ondelete="SET NULL")
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    assignee: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING")
    priority_band: Mapped[str] = mapped_column(String(20), nullable=False)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    target_date: Mapped[date | None] = mapped_column(Date)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now(), nullable=False
    )

    plan: Mapped[RemediationPlanORM] = relationship(back_populates="tasks")


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
