#!/usr/bin/env python3
# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Phase Gateway — pipeline de verificação sequencial entre fases de ataque.

Cada módulo de ataque com múltiplos pré-requisitos usa ``PhaseGateway`` para
garantir que nenhuma fase avance enquanto a anterior não for satisfeita.

Uso típico:

    from wirelessxpl.core.phase_gateway import PhaseGateway

    gw = PhaseGateway("Z-Wave RCE")
    gw.phase("Hardware", lambda: validator.require(Requirement.ZWAVE_DONGLE))
    gw.phase("Libraries", lambda: validator.require(Requirement.PYSERIAL))
    gw.phase("Scope",    lambda: i_know_scope)
    gw.phase("Compile",  lambda: orch.compile(Lang.C, poc_path)[0])
    if not gw.run():
        return

Version: 1.0.0
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resultado de fase individual
# ---------------------------------------------------------------------------

@dataclass
class PhaseResult:
    """Resultado de uma fase única do gateway."""

    name: str
    passed: bool
    elapsed_ms: float = 0.0
    detail: str = ""
    fix_hint: str = ""

    @property
    def status_icon(self) -> str:
        return "OK  " if self.passed else "FAIL"


# ---------------------------------------------------------------------------
# Relatório consolidado
# ---------------------------------------------------------------------------

@dataclass
class GatewayReport:
    """Relatório de execução de todas as fases de um gateway."""

    module_name: str
    results: List[PhaseResult] = field(default_factory=list)
    aborted_at: Optional[str] = None

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def first_failure(self) -> Optional[PhaseResult]:
        for r in self.results:
            if not r.passed:
                return r
        return None

    def print_report(self) -> None:
        """Imprime a tabela de resultado de cada fase."""
        width = 60
        print()
        print("=" * width)
        print(f"  Phase Gateway — {self.module_name}")
        print("=" * width)
        print(f"  {'Phase':<20} {'Status':<6}  {'ms':>6}  Detail")
        print("-" * width)
        for r in self.results:
            detail = r.detail[:28] if r.detail else ""
            print(f"  {r.name:<20} [{r.status_icon}]  {r.elapsed_ms:>6.1f}  {detail}")
            if not r.passed and r.fix_hint:
                print(f"    {'':>20}  hint: {r.fix_hint}")
        print("-" * width)
        if self.all_passed:
            print(f"  All {len(self.results)} phases passed. Proceeding.")
        else:
            print(f"  BLOCKED at phase '{self.aborted_at}'. Aborting.")
        print("=" * width)
        print()


# ---------------------------------------------------------------------------
# Gateway principal
# ---------------------------------------------------------------------------

class PhaseGateway:
    """Executa uma sequência de fases onde cada uma deve passar antes da próxima.

    Args:
        module_name: Nome do módulo ou ataque — aparece no cabeçalho do relatório.
        stop_on_first_failure: Se True (padrão), interrompe ao encontrar a primeira
            fase que falhou. Se False, executa todas as fases e reporta todas as
            falhas.
        silent: Se True, não imprime o relatório ao terminar.
    """

    def __init__(
        self,
        module_name: str,
        stop_on_first_failure: bool = True,
        silent: bool = False,
    ) -> None:
        self.module_name = module_name
        self.stop_on_first_failure = stop_on_first_failure
        self.silent = silent
        self._phases: List[tuple[str, Callable[[], bool], str]] = []

    # ------------------------------------------------------------------
    # API de construção
    # ------------------------------------------------------------------

    def phase(
        self,
        name: str,
        check: Callable[[], bool],
        fix_hint: str = "",
    ) -> "PhaseGateway":
        """Adiciona uma fase ao pipeline.

        Args:
            name: Nome curto da fase (ex.: "Hardware", "Scope", "Compile").
            check: Callable que retorna True (passou) ou False (falhou).
                   Exceções internas são capturadas e tratadas como falha.
            fix_hint: Dica de correção exibida quando a fase falha.

        Returns:
            self — permite encadeamento fluente.
        """
        self._phases.append((name, check, fix_hint))
        return self

    # ------------------------------------------------------------------
    # Execução
    # ------------------------------------------------------------------

    def run(self) -> bool:
        """Executa todas as fases em sequência.

        Returns:
            True se todas as fases passaram; False caso contrário.
        """
        report = GatewayReport(module_name=self.module_name)

        for name, check, fix_hint in self._phases:
            t0 = time.perf_counter()
            try:
                passed = bool(check())
                detail = ""
            except Exception as exc:  # noqa: BLE001
                passed = False
                detail = f"Exception: {type(exc).__name__}: {exc}"
                logger.debug("Phase '%s' raised: %s", name, exc, exc_info=True)

            elapsed_ms = (time.perf_counter() - t0) * 1000
            result = PhaseResult(
                name=name,
                passed=passed,
                elapsed_ms=elapsed_ms,
                detail=detail,
                fix_hint=fix_hint,
            )
            report.results.append(result)

            if not passed:
                report.aborted_at = name
                if self.stop_on_first_failure:
                    # Preenche as fases restantes como skipped
                    remaining = self._phases[len(report.results):]
                    for rname, _, rhint in remaining:
                        report.results.append(
                            PhaseResult(
                                name=rname,
                                passed=False,
                                elapsed_ms=0.0,
                                detail="skipped (previous phase failed)",
                                fix_hint=rhint,
                            )
                        )
                    break

        if not self.silent:
            report.print_report()

        return report.all_passed

    # ------------------------------------------------------------------
    # Utilitários
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Remove todas as fases registradas."""
        self._phases.clear()

    def __len__(self) -> int:
        return len(self._phases)

    def __repr__(self) -> str:
        return f"PhaseGateway({self.module_name!r}, phases={len(self._phases)})"


# ---------------------------------------------------------------------------
# Helpers de conveniência
# ---------------------------------------------------------------------------

def quick_gate(module_name: str, **phases: Callable[[], bool]) -> bool:
    """Cria e executa um gateway com fases definidas como kwargs.

    Exemplo::

        ok = quick_gate(
            "BLE Scan",
            Hardware=lambda: validator.require(Requirement.BLUETOOTH_ADAPTER),
            Root=lambda: os.geteuid() == 0,
        )

    Args:
        module_name: Nome do módulo para o cabeçalho.
        **phases: Mapeamento nome→callable na ordem em que devem ser executadas.

    Returns:
        True se todas as fases passaram.
    """
    gw = PhaseGateway(module_name)
    for name, check in phases.items():
        gw.phase(name, check)
    return gw.run()
