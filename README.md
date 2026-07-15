# DevSecPerOps — Entorno de validación del modelo

Repositorio de la **puesta en práctica** del modelo de gobernanza de calidad
**DevSecPerOps** (sección 4.2 del TFM). Implementa un pipeline CI/CD completo que
integra controles de calidad funcional, seguridad y rendimiento, gobernados
mediante *quality gates* automatizados.

La aplicación de prueba es una **API REST de gestión de tareas y proyectos**
(FastAPI + SQLite + JWT) que originalmente contenía **defectos sembrados y
documentados**, ya **remediados** (apartado 7), para demostrar el ciclo completo
de gobernanza: detección → bloqueo → remediación → aprobación automática del
despliegue.

---

## 1. Arquitectura del repositorio

```
devsecperops-validation/
├── app/                     API FastAPI (defectos sembrados, ya remediados)
├── tests/                   Pruebas pytest (cobertura ~97 %)
├── k6/load-test.js          Prueba de carga (Performance Gate)
├── scripts/check_gates.py   Evaluación consolidada de los Quality Gates
│                            (incluye umbral adaptativo del Performance Gate)
├── sonar-project.properties Configuración de SonarQube (SAST + cobertura)
├── k8s/                     Manifiestos de despliegue (Kubernetes)
├── monitoring/              Configuración de Prometheus
├── .github/workflows/       Pipeline DevSecPerOps (flujo operativo, Tabla 15)
├── .metrics/                Histórico de p95 para el umbral adaptativo
│                            (persistido en CI vía actions/cache; no versionado)
├── Dockerfile
├── docker-compose.yml       Entorno local: API + SonarQube + Prometheus + Grafana
└── requirements.txt         (PyYAML actualizado, sin vulnerabilidades conocidas)
```

## 2. Defectos originalmente sembrados y gate que disparaban

Estos defectos se introdujeron de forma deliberada para validar la capacidad de
detección del modelo, y fueron remediados íntegramente en un segundo ciclo
(apartado 7). Se documentan aquí por trazabilidad.

| Defecto | Control | Gate | Archivo | Estado |
|---|---|---|---|---|
| Inyección SQL por concatenación | SonarQube (SAST) + OWASP ZAP (DAST activo) | Vulnerability | `app/main.py` (`/tasks/search`) | ✅ Remediado (parámetros enlazados) |
| Secreto embebido en código | SonarQube (SAST) | Quality | `app/auth.py` | ✅ Remediado (variable de entorno) |
| `yaml.load` inseguro | SonarQube (SAST) | Quality | `app/config.py` | ✅ Remediado (`yaml.safe_load`) |
| Dependencia con CVE (PyYAML 5.3.1) | OWASP Dependency-Check | Dependency | `requirements.txt` | ✅ Remediado (PyYAML 6.0.2) |
| XSS reflejado / sin cabeceras | OWASP ZAP (DAST) | Vulnerability | `app/main.py` (`/echo`) | ✅ Remediado (`html.escape` + cabeceras CSP) |
| Endpoint lento (latencia inyectada) | k6 | Performance | `app/main.py` (`/reports`) | ✅ Remediado (`report_delay_ms: 0`) |
| Cobertura < 80 % | pytest + SonarQube | Coverage | `tests/test_api.py` | ✅ Remediado (~97 % cobertura) |

## 3. Requisitos previos

- Docker y Docker Compose
- Python 3.11
- Cuenta de GitHub (para ejecutar el workflow) **o** ejecución local (apartado 5)
- k6 ([instalación](https://k6.io/docs/get-started/installation/))

## 4. Ejecución del pipeline completo en GitHub Actions

1. Haz `git push` a `main` (o dispara manualmente con `workflow_dispatch`). El
   workflow se ejecuta automáticamente.
2. El análisis dinámico (DAST) se ejecuta en modo **activo** (`zap-api-scan.py`
   contra la especificación OpenAPI de la API), no en modo baseline/pasivo — por
   eso esta etapa tarda varios minutos.
3. Con el código actual (ya remediado), los **4 quality gates deben pasar** y el
   despliegue se autoriza automáticamente. Si quieres reproducir el escenario
   original de bloqueo, revierte los cambios del apartado 7 sobre una rama de
   prueba.
4. Revisa la pestaña **Actions** para ver el detalle de cada gate y descargar los
   artefactos (`gates-summary.json`, `zap-report.json`, `coverage.xml`,
   `dependency-check-report.json`, `k6-summary.json`,
   `performance_history.json`).

## 5. Ejecución local (alternativa, sin GitHub)

```bash
# 1. Entorno y dependencias
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Pruebas + cobertura  -> genera coverage.xml
pytest --cov=app --cov-report=xml --cov-report=term

# 3. Levantar la pila (API + SonarQube + Prometheus + Grafana)
docker compose up -d
#    SonarQube: http://localhost:9000  (admin/admin)
#    Grafana:   http://localhost:3000  (admin/admin)

# 4. SAST + cobertura en SonarQube (instala sonar-scanner antes)
sonar-scanner -Dsonar.login=TU_TOKEN

# 5. Análisis de dependencias (OWASP Dependency-Check CLI)
dependency-check --project devsecperops --scan . -f JSON -o reports

# 6. DAST activo con OWASP ZAP, contra la especificación OpenAPI
#    (con la API levantada en :8000)
docker run --rm --network host -v "$(pwd)/zap-out:/zap/wrk:rw" \
  ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py \
  -t http://localhost:8000/openapi.json -f openapi \
  -J zap-report.json -I

# 7. Prueba de carga con k6  -> genera k6-summary.json
k6 run --summary-export=k6-summary.json k6/load-test.js

# 8. Evaluación consolidada de los Quality Gates
python scripts/check_gates.py \
  --coverage coverage.xml \
  --dependency reports/dependency-check-report.json \
  --zap zap-report.json \
  --k6 k6-summary.json \
  --history .metrics/performance_history.json
```

> El Performance Gate usa un umbral **adaptativo** (media + 3σ del histórico de
> p95, carta de control de Shewhart), calibrado a partir de
> `.metrics/performance_history.json`. Mientras no haya al menos 5 muestras
> acumuladas, se aplica un umbral estático de salvaguarda (500 ms). En CI, este
> archivo se persiste entre ejecuciones de la misma rama mediante
> `actions/cache` (ver el workflow). Confirmado empíricamente: a partir de la
> 6ª ejecución sobre esta rama, el modo pasó a adaptativo (umbral calibrado en
> ~50 ms, muy por debajo del umbral estático original de 500 ms, reflejando el
> buen rendimiento real y estable de la API).

## 6. Resultados de la validación

Se documentaron dos ciclos de ejecución (ver TFM, apartado 4.2 y Anexo A):

| Quality Gate | 1ª ejecución (con defectos) | 2ª ejecución (remediada) |
|---|---|---|
| Coverage Gate | 91,75 % — Passed | 96,68 % — Passed |
| Dependency Gate | 1 dependencia crítica — Failed | 0 dependencias críticas — Passed |
| Vulnerability Gate (DAST) | 3 alertas medias/altas — Failed | 0 alertas — Passed |
| Performance Gate | p95 = 1.203,54 ms — Failed | p95 = 3,93 ms — Passed |
| **Dictamen de gobernanza** | **Pipeline bloqueado** | **Despliegue autorizado** |

El análisis dinámico activo detectó de forma independiente la inyección SQL
—la misma vulnerabilidad ya señalada por el análisis estático (SonarQube)—,
evidenciando la complementariedad real entre SAST y DAST activo.

Los artefactos JSON completos de ambas ejecuciones están disponibles como
artifacts descargables en la pestaña **Actions** de cada run correspondiente.

## 7. Remediación aplicada (segunda ejecución)

Para cerrar el ciclo de gobernanza y conseguir que todos los gates pasen, se
aplicaron las siguientes remediaciones:

1. `app/auth.py`: `SECRET_KEY` ya no está hardcodeada — se lee de `os.environ`,
   con un valor aleatorio de un solo uso como salvaguarda en entornos de CI
   efímeros.
2. `app/config.py`: `yaml.load` sustituido por `yaml.safe_load`.
3. `app/main.py` (`/tasks/search`): la consulta usa parámetros enlazados en
   lugar de concatenación de cadenas, eliminando la inyección SQL.
4. `app/main.py` (`/echo`): la entrada se escapa con `html.escape`, y se añadió
   un middleware (`SecurityHeadersMiddleware`) que aplica cabeceras de
   seguridad completas (CSP con `frame-ancestors`, `object-src`, `base-uri` y
   `form-action` explícitos, `X-Frame-Options`, `X-Content-Type-Options`,
   `Permissions-Policy` y cabeceras `Cross-Origin-*`).
5. `requirements.txt`: `PyYAML` actualizado a `6.0.2` (sin CVE conocido).
6. `config.yaml`: `report_delay_ms: 0` (latencia artificial eliminada).
7. `tests/test_api.py`: pruebas añadidas para `/tasks/search`, `/echo` y
   `/reports`, incluyendo casos que confirman explícitamente la neutralización
   del intento de inyección SQL y del XSS reflejado. Cobertura resultante:
   ~97 %.

Adicionalmente, como mejora metodológica más allá del alcance original, se
implementó el **umbral adaptativo** del Performance Gate (apartado 5) y se
migró el análisis dinámico de modo *baseline* (pasivo) a modo **activo**
(apartado 4), adelantando dos de las líneas de trabajo futuro planteadas en el
TFM.
