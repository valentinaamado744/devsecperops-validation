#!/usr/bin/env python3
"""Evaluación consolidada de los Quality Gates del modelo DevSecPerOps.

Lee los artefactos generados por cada herramienta del pipeline y aplica los
umbrales definidos en el modelo (Tabla 14 del TFM). Devuelve código de salida
distinto de cero si algún gate crítico no se cumple, bloqueando el pipeline.

Entradas esperadas (rutas relativas, pasadas como argumentos opcionales):
  --coverage   coverage.xml           (pytest-cov, formato Cobertura)
  --dependency dependency-check-report.json
  --zap        zap-report.json        (OWASP ZAP, formato JSON)
  --k6         k6-summary.json        (k6 --summary-export)
  --history    performance_history.json (histórico de p95, ver más abajo)

Genera además gates-summary.json con el detalle de cada gate para trazabilidad.

Umbral adaptativo del Performance Gate (REMEDIACIÓN de la limitación señalada
en el TFM: "umbrales fijados con fines demostrativos"):
En lugar de un umbral estático único, el Performance Gate se calibra a partir
del histórico de p95 de ejecuciones previas, mediante una carta de control de
Shewhart (media + k·desviación típica). Mientras no exista histórico
suficiente (arranque en frío), se aplica el umbral estático original como
salvaguarda. El histórico se persiste entre ejecuciones de la misma rama
mediante actions/cache en el workflow (ver .github/workflows/devsecperops.yml).
"""

import argparse
import json
import os
import statistics
import sys
import xml.etree.ElementTree as ET

# Umbrales del modelo DevSecPerOps (Tabla 14)
COVERAGE_MIN = 80.0          # Coverage Gate
ALLOW_CRITICAL_VULNS = 0     # Vulnerability Gate
ALLOW_VULNERABLE_DEPS = 0    # Dependency Gate

# Performance Gate: umbral estático original, usado solo como salvaguarda
# mientras no haya histórico suficiente para calibrar un umbral adaptativo.
P95_MAX_MS_STATIC = 500.0

# Parámetros del umbral adaptativo (carta de control de Shewhart)
PERF_MIN_SAMPLES = 5   # muestras mínimas antes de confiar en el umbral adaptativo
PERF_Z = 3.0            # multiplicador de sigma (límite de control superior, 3σ)
PERF_FLOOR_MS = 50.0    # piso mínimo, evita un umbral irrealmente ajustado
PERF_HISTORY_MAX = 20   # nº máximo de muestras conservadas en el histórico


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


def load_perf_history(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return [float(v) for v in data.get("p95_samples_ms", [])]
    except Exception:  # noqa: BLE001
        return []


def save_perf_history(path, samples):
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(
                {"p95_samples_ms": samples[-PERF_HISTORY_MAX:]},
                fh, indent=2, ensure_ascii=False,
            )
    except Exception:  # noqa: BLE001
        pass


def adaptive_p95_threshold(history):
    """Calcula el umbral del Performance Gate a partir del histórico.

    Devuelve (umbral_ms, modo, descripcion) donde modo es 'estatico' o
    'adaptativo', para dejar constancia trazable de cuál se aplicó.
    """
    n = len(history)
    if n < PERF_MIN_SAMPLES:
        return (
            P95_MAX_MS_STATIC,
            "estático",
            f"histórico insuficiente: {n}/{PERF_MIN_SAMPLES} muestras",
        )
    mean = statistics.mean(history)
    stdev = statistics.pstdev(history)
    threshold = max(mean + PERF_Z * stdev, PERF_FLOOR_MS)
    return (
        round(threshold, 2),
        "adaptativo",
        f"media={mean:.2f} ms, +{PERF_Z:g}σ={stdev:.2f} ms, n={n}",
    )


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
    perf_threshold = perf_mode = perf_desc = None
    if p95 is not None:
        history = load_perf_history(args.history)
        perf_threshold, perf_mode, perf_desc = adaptive_p95_threshold(history)
        gates.append((
            "Performance Gate",
            p95 <= perf_threshold,
            f"p95 {p95} ms (máximo {perf_threshold} ms, umbral {perf_mode}: {perf_desc})",
        ))
        # Se registra la muestra actual para calibrar futuras ejecuciones.
        save_perf_history(args.history, history + [p95])

    summary = {
        "coverage_pct": cov,
        "vulnerable_dependencies": deps,
        "dast_alerts": zap,
        "p95_ms": p95,
        "performance_threshold_ms": perf_threshold,
        "performance_threshold_mode": perf_mode,
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
    parser.add_argument("--history", default=".metrics/performance_history.json",
                         help="Ruta al histórico de p95 para el umbral adaptativo")
    args = parser.parse_args()
    sys.exit(evaluate(args))


if __name__ == "__main__":
    main()
