#!/usr/bin/env python3
"""Evaluación consolidada de los Quality Gates del modelo DevSecPerOps.

Lee los artefactos generados por cada herramienta del pipeline y aplica los
umbrales definidos en el modelo (Tabla 14 del TFM). Devuelve código de salida
distinto de cero si algún gate crítico no se cumple, bloqueando el pipeline.

Entradas esperadas (rutas relativas, pasadas como argumentos opcionales):
  --coverage   coverage.xml           (pytest-cov, formato Cobertura)
  --dependency dependency-check-report.json
  --zap        zap-report.json        (OWASP ZAP baseline, formato JSON)
  --k6         k6-summary.json        (k6 --summary-export)

Genera además gates-summary.json con el detalle de cada gate para trazabilidad.
"""

import argparse
import json
import sys
import xml.etree.ElementTree as ET

# Umbrales del modelo DevSecPerOps (Tabla 14)
COVERAGE_MIN = 80.0          # Coverage Gate
P95_MAX_MS = 500.0           # Performance Gate
ALLOW_CRITICAL_VULNS = 0     # Vulnerability Gate
ALLOW_VULNERABLE_DEPS = 0    # Dependency Gate


def read_coverage(path):
    try:
        root = ET.parse(path).getroot()
        rate = float(root.get("line-rate", 0)) * 100
        return round(rate, 2)
    except Exception as exc:  # noqa: BLE001
        return None if exc else None


def read_dependency(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        count = 0
        for dep in data.get("dependencies", []):
            vulns = dep.get("vulnerabilities", [])
            count += len([v for v in vulns if v.get("severity", "").upper()
                          in ("CRITICAL", "HIGH")])
        return count
    except Exception:  # noqa: BLE001
        return None


def read_zap(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        high = 0
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                # riskcode: 3 = High, 2 = Medium, 1 = Low
                if int(alert.get("riskcode", 0)) >= 2:
                    high += 1
        return high
    except Exception:  # noqa: BLE001
        return None


def read_k6(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        metrics = data.get("metrics", {})
        dur = metrics.get("http_req_duration", {})
        p95 = dur.get("p(95)") or dur.get("values", {}).get("p(95)")
        return round(float(p95), 2) if p95 is not None else None
    except Exception:  # noqa: BLE001
        return None


def evaluate(args):
    gates = []

    cov = read_coverage(args.coverage) if args.coverage else None
    if cov is not None:
        gates.append(("Coverage Gate", cov >= COVERAGE_MIN,
                      f"cobertura {cov}% (mínimo {COVERAGE_MIN}%)"))

    deps = read_dependency(args.dependency) if args.dependency else None
    if deps is not None:
        gates.append(("Dependency Gate", deps <= ALLOW_VULNERABLE_DEPS,
                      f"{deps} dependencias críticas/altas (máximo {ALLOW_VULNERABLE_DEPS})"))

    zap = read_zap(args.zap) if args.zap else None
    if zap is not None:
        gates.append(("Vulnerability Gate (DAST)", zap <= ALLOW_CRITICAL_VULNS,
                      f"{zap} alertas medias/altas (máximo {ALLOW_CRITICAL_VULNS})"))

    p95 = read_k6(args.k6) if args.k6 else None
    if p95 is not None:
        gates.append(("Performance Gate", p95 <= P95_MAX_MS,
                      f"p95 {p95} ms (máximo {P95_MAX_MS} ms)"))

    summary = {
        "coverage_pct": cov,
        "vulnerable_dependencies": deps,
        "dast_alerts": zap,
        "p95_ms": p95,
        "gates": [
            {"name": n, "passed": bool(p), "detail": d} for n, p, d in gates
        ],
    }
    with open("gates-summary.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    print("=" * 60)
    print("  EVALUACIÓN DE QUALITY GATES - DevSecPerOps")
    print("=" * 60)
    failed = 0
    for name, passed, detail in gates:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {name}: {detail}")
        if not passed:
            failed += 1
    print("=" * 60)

    if failed:
        print(f"  Resultado: PIPELINE BLOQUEADO ({failed} gate/s no superado/s)")
        return 1
    print("  Resultado: TODOS LOS GATES SUPERADOS - despliegue autorizado")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Evaluación de Quality Gates DevSecPerOps")
    parser.add_argument("--coverage")
    parser.add_argument("--dependency")
    parser.add_argument("--zap")
    parser.add_argument("--k6")
    args = parser.parse_args()
    sys.exit(evaluate(args))


if __name__ == "__main__":
    main()
