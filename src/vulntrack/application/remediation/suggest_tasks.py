"""T-067: Caso de uso SuggestTasks — genera tareas de remediación inteligentes."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from vulntrack.domain.entities.finding import Finding
from vulntrack.domain.entities.remediation import RemediationTask, TaskStatus
from vulntrack.domain.ports.finding_repository import FindingRepository
from vulntrack.domain.ports.kev_repository import KevRepository
from vulntrack.domain.ports.remediation_repository import RemediationRepository
from vulntrack.domain.services.kev_matcher import KevMatcher
from vulntrack.domain.services.prioritization import PrioritizationService, PriorityWeights
from vulntrack.domain.value_objects.priority_score import PriorityBand, PriorityScore
from vulntrack.domain.value_objects.severity import Severity

# Days to remediation target by finding type
_KEV_DAYS = 7
_HIGH_EPSS_DAYS = 30
_CRITICAL_DAYS = 60
_HIGH_DAYS = 90
_DEFAULT_DAYS = 180


@dataclass
class AdvisorConfig:
    epss_high_threshold: float = 0.40
    cvss_high_threshold: float = 7.0


class RemediationAdvisor:
    def __init__(self, config: AdvisorConfig | None = None) -> None:
        self.config = config or AdvisorConfig()

    def suggest(
        self,
        finding: Finding,
        is_in_kev: bool,
        score: PriorityScore,
        today: date | None = None,
    ) -> dict[str, object]:
        ref = today or date.today()

        if is_in_kev:
            return {
                "title": f"Remediar {finding.vuln_id} en {finding.component_name}",
                "recommended_action": "Explotación activa confirmada en catálogo CISA KEV. "
                                      "Aplicar parche o mitigación inmediatamente.",
                "target_date": ref + timedelta(days=_KEV_DAYS),
                "priority_band": PriorityBand.IMMEDIATE,
            }

        epss = finding.epss_score or 0.0
        if epss >= self.config.epss_high_threshold:
            return {
                "title": f"Remediar {finding.vuln_id} en {finding.component_name}",
                "recommended_action": (
                    f"Alta probabilidad de explotación (EPSS={epss:.0%}). "
                    "Actualizar componente o aplicar workaround en 30 días."
                ),
                "target_date": ref + timedelta(days=_HIGH_EPSS_DAYS),
                "priority_band": score.band,
            }

        if finding.severity == Severity.CRITICAL:
            return {
                "title": f"Remediar {finding.vuln_id} en {finding.component_name}",
                "recommended_action": (
                    "Vulnerabilidad crítica. Actualizar componente y verificar "
                    "ausencia de indicios de explotación en un plazo de 60 días."
                ),
                "target_date": ref + timedelta(days=_CRITICAL_DAYS),
                "priority_band": score.band,
            }

        if finding.severity == Severity.HIGH:
            return {
                "title": f"Remediar {finding.vuln_id} en {finding.component_name}",
                "recommended_action": (
                    "Vulnerabilidad alta. Planificar actualización del componente "
                    "en el próximo ciclo de release (90 días)."
                ),
                "target_date": ref + timedelta(days=_HIGH_DAYS),
                "priority_band": score.band,
            }

        return {
            "title": f"Evaluar {finding.vuln_id} en {finding.component_name}",
            "recommended_action": (
                "Vulnerabilidad de severidad media/baja. Incluir en el backlog "
                "de deuda técnica y remediar en el próximo mantenimiento."
            ),
            "target_date": ref + timedelta(days=_DEFAULT_DAYS),
            "priority_band": score.band,
        }


class SuggestTasksUseCase:
    def __init__(
        self,
        finding_repo: FindingRepository,
        kev_repo: KevRepository,
        remediation_repo: RemediationRepository,
        weights: PriorityWeights | None = None,
        config: AdvisorConfig | None = None,
    ) -> None:
        self._finding_repo = finding_repo
        self._kev_repo = kev_repo
        self._remediation_repo = remediation_repo
        self._svc = PrioritizationService(weights)
        self._advisor = RemediationAdvisor(config)

    async def execute(self, plan_id: int) -> list[RemediationTask]:
        plan = await self._remediation_repo.get_plan(plan_id)
        if plan is None:
            return []

        findings = await self._finding_repo.list_by_project(plan.project_uuid)
        kev_entries = await self._kev_repo.list_all()
        matcher = KevMatcher(kev_entries)

        now = datetime.now(UTC)
        today = date.today()
        created_tasks: list[RemediationTask] = []

        # Sort by priority score desc before creating tasks
        scored = sorted(
            [(f, self._svc.score(f, matcher.is_in_kev(f.vuln_id))) for f in findings],
            key=lambda x: x[1].value,
            reverse=True,
        )

        for finding, score in scored:
            in_kev = matcher.is_in_kev(finding.vuln_id)
            suggestion = self._advisor.suggest(finding, in_kev, score, today)

            task = await self._remediation_repo.create_task(
                plan_id,
                finding_id=finding.id,
                title=suggestion["title"],
                description=suggestion["recommended_action"],
                assignee=None,
                status=TaskStatus.PENDING,
                priority_band=suggestion["priority_band"],
                recommended_action=suggestion["recommended_action"],
                target_date=suggestion["target_date"],
                completed_at=None,
                notes=None,
                created_at=now,
                updated_at=now,
            )
            created_tasks.append(task)

        return created_tasks
