"""Tests T-067: SuggestTasksUseCase y transiciones de UpdateTask."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from unittest.mock import AsyncMock

import pytest

from vulntrack.application.remediation.create_plan import CreatePlanUseCase
from vulntrack.application.remediation.suggest_tasks import (
    AdvisorConfig,
    RemediationAdvisor,
    SuggestTasksUseCase,
)
from vulntrack.application.remediation.update_task import (
    InvalidTaskTransitionError,
    UpdateTaskUseCase,
)
from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.kev_entry import KevEntry
from vulntrack.domain.entities.remediation import RemediationPlan, RemediationTask, TaskStatus
from vulntrack.domain.value_objects.priority_score import PriorityBand, PriorityScore
from vulntrack.domain.value_objects.severity import Severity


def _finding(
    f_id: int = 1, sev: Severity = Severity.CRITICAL,
    vuln_id: str = "CVE-A", cvss: float | None = 9.8, epss: float | None = 0.85,
) -> Finding:
    return Finding(
        id=f_id, project_uuid="u1", dt_finding_uuid=f"dt-{f_id}",
        component_name="log4j-core", component_version="2.14.0", component_group=None,
        vuln_id=vuln_id, vuln_source="NVD", severity=sev,
        cvss_v3_base_score=cvss, epss_score=epss, epss_percentile=None,
        attributed_on=None, suppressed=False, last_synced_at=datetime.now(UTC),
    )


def _kev(cve_id: str) -> KevEntry:
    return KevEntry(
        cve_id=cve_id, vendor_project="V", product="P", vulnerability_name="V",
        date_added=date(2026, 1, 1), short_description="d", required_action="patch",
        due_date=None, notes=None,
    )


def _plan(plan_id: int = 1) -> RemediationPlan:
    now = datetime.now(UTC)
    return RemediationPlan(
        id=plan_id, project_uuid="u1", name="Plan Q2",
        description=None, created_at=now, updated_at=now,
    )


def _task(t_id: int = 1, status: TaskStatus = TaskStatus.PENDING) -> RemediationTask:
    now = datetime.now(UTC)
    return RemediationTask(
        id=t_id, plan_id=1, finding_id=1, title="Fix CVE-A",
        description=None, assignee=None, status=status,
        priority_band=PriorityBand.IMMEDIATE, recommended_action="patch",
        target_date=None, completed_at=None, notes=None,
        created_at=now, updated_at=now,
    )


# ─── RemediationAdvisor unit tests ────────────────────────────────────────────

class TestRemediationAdvisor:
    def test_kev_finding_gets_7_day_target(self) -> None:
        advisor = RemediationAdvisor()
        f = _finding(vuln_id="CVE-KEV")
        score = PriorityScore(value=92.5, band=PriorityBand.IMMEDIATE, is_kev=True, breakdown={})
        today = date(2026, 6, 25)

        result = advisor.suggest(f, is_in_kev=True, score=score, today=today)

        assert result["target_date"] == today + timedelta(days=7)
        assert "Explotación activa confirmada" in str(result["recommended_action"])
        assert result["priority_band"] == PriorityBand.IMMEDIATE

    def test_high_epss_gets_30_day_target(self) -> None:
        advisor = RemediationAdvisor(AdvisorConfig(epss_high_threshold=0.40))
        f = _finding(vuln_id="CVE-EPSS", epss=0.75)
        score = PriorityScore(value=60.0, band=PriorityBand.HIGH, is_kev=False, breakdown={})
        today = date(2026, 6, 25)

        result = advisor.suggest(f, is_in_kev=False, score=score, today=today)

        assert result["target_date"] == today + timedelta(days=30)
        assert "EPSS" in str(result["recommended_action"])

    def test_critical_no_kev_gets_60_day_target(self) -> None:
        advisor = RemediationAdvisor()
        f = _finding(sev=Severity.CRITICAL, epss=0.05)
        score = PriorityScore(value=45.0, band=PriorityBand.MEDIUM, is_kev=False, breakdown={})
        today = date(2026, 6, 25)

        result = advisor.suggest(f, is_in_kev=False, score=score, today=today)

        assert result["target_date"] == today + timedelta(days=60)

    def test_high_severity_gets_90_day_target(self) -> None:
        advisor = RemediationAdvisor()
        f = _finding(sev=Severity.HIGH, epss=0.05)
        score = PriorityScore(value=30.0, band=PriorityBand.MEDIUM, is_kev=False, breakdown={})
        today = date(2026, 6, 25)

        result = advisor.suggest(f, is_in_kev=False, score=score, today=today)

        assert result["target_date"] == today + timedelta(days=90)


# ─── SuggestTasksUseCase ──────────────────────────────────────────────────────

class TestSuggestTasksUseCase:
    def _make_uc(
        self,
        findings: list[Finding],
        kev_entries: list[KevEntry] = [],
        plan: RemediationPlan | None = None,
    ) -> tuple[SuggestTasksUseCase, AsyncMock]:
        finding_repo = AsyncMock()
        finding_repo.list_by_project.return_value = findings
        kev_repo = AsyncMock()
        kev_repo.list_all.return_value = kev_entries
        remediation_repo = AsyncMock()
        remediation_repo.get_plan.return_value = plan or _plan()

        now = datetime.now(UTC)

        async def create_task_mock(plan_id: int, **fields: object) -> RemediationTask:
            return RemediationTask(
                id=1, plan_id=plan_id, finding_id=fields.get("finding_id"),  # type: ignore
                title=str(fields.get("title", "")),
                description=str(fields.get("description", "")),
                assignee=None, status=TaskStatus.PENDING,
                priority_band=fields.get("priority_band", PriorityBand.LOW),  # type: ignore
                recommended_action=str(fields.get("recommended_action", "")),
                target_date=fields.get("target_date"),  # type: ignore
                completed_at=None, notes=None,
                created_at=now, updated_at=now,
            )

        remediation_repo.create_task.side_effect = create_task_mock

        uc = SuggestTasksUseCase(finding_repo, kev_repo, remediation_repo)
        return uc, remediation_repo

    @pytest.mark.asyncio
    async def test_kev_finding_creates_task_with_7_day_target(self) -> None:
        f = _finding(vuln_id="CVE-2024-1234", cvss=9.8, epss=0.85)
        uc, repo = self._make_uc([f], kev_entries=[_kev("CVE-2024-1234")])

        tasks = await uc.execute(plan_id=1)

        assert len(tasks) == 1
        assert "Explotación activa confirmada" in (tasks[0].recommended_action or "")
        expected_date = date.today() + timedelta(days=7)
        assert tasks[0].target_date == expected_date

    @pytest.mark.asyncio
    async def test_plan_not_found_returns_empty(self) -> None:
        finding_repo = AsyncMock()
        kev_repo = AsyncMock()
        kev_repo.list_all.return_value = []
        remediation_repo = AsyncMock()
        remediation_repo.get_plan.return_value = None

        uc = SuggestTasksUseCase(finding_repo, kev_repo, remediation_repo)
        tasks = await uc.execute(plan_id=999)

        assert tasks == []

    @pytest.mark.asyncio
    async def test_tasks_ordered_by_priority_desc(self) -> None:
        findings = [
            _finding(1, sev=Severity.LOW, vuln_id="CVE-LOW", cvss=2.0, epss=0.01),
            _finding(2, sev=Severity.CRITICAL, vuln_id="CVE-HIGH", cvss=9.8, epss=0.9),
        ]
        uc, repo = self._make_uc(findings)
        tasks = await uc.execute(plan_id=1)

        # The calls to create_task should be in score DESC order
        calls = repo.create_task.call_args_list
        assert len(calls) == 2
        # First call should be for the critical finding
        assert "CVE-HIGH" in str(calls[0])


# ─── UpdateTaskUseCase (transiciones) ─────────────────────────────────────────

class TestUpdateTaskTransitions:
    @pytest.mark.asyncio
    async def test_invalid_transition_completed_to_pending(self) -> None:
        repo = AsyncMock()
        uc = UpdateTaskUseCase(repo)
        task = _task(status=TaskStatus.COMPLETED)

        with pytest.raises(InvalidTaskTransitionError):
            await uc.execute_with_validation(task, status=TaskStatus.PENDING)

    @pytest.mark.asyncio
    async def test_valid_transition_pending_to_in_progress(self) -> None:
        repo = AsyncMock()
        repo.update_task.return_value = _task(status=TaskStatus.IN_PROGRESS)
        uc = UpdateTaskUseCase(repo)
        task = _task(status=TaskStatus.PENDING)

        result = await uc.execute_with_validation(task, status=TaskStatus.IN_PROGRESS)

        assert result.status == TaskStatus.IN_PROGRESS
        repo.update_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_completed_sets_completed_at(self) -> None:
        repo = AsyncMock()
        now = datetime.now(UTC)
        repo.update_task.return_value = _task(status=TaskStatus.COMPLETED)
        uc = UpdateTaskUseCase(repo)
        task = _task(status=TaskStatus.IN_PROGRESS)

        await uc.execute_with_validation(task, status=TaskStatus.COMPLETED)

        kwargs = repo.update_task.call_args[1]
        assert kwargs["completed_at"] is not None


# ─── CreatePlanUseCase ────────────────────────────────────────────────────────

class TestCreatePlanUseCase:
    @pytest.mark.asyncio
    async def test_creates_plan_via_repo(self) -> None:
        repo = AsyncMock()
        plan = _plan()
        repo.create_plan.return_value = plan

        uc = CreatePlanUseCase(repo)
        result = await uc.execute("u1", "Plan Q2 2026", "Descripción")

        repo.create_plan.assert_called_once_with("u1", "Plan Q2 2026", "Descripción")
        assert result.id == 1
        assert result.name == "Plan Q2"
