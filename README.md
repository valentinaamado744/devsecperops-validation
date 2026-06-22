# DevSecPerOps — Entorno de validación del modelo

Repositorio de la **puesta en práctica** del modelo de gobernanza de calidad
**DevSecPerOps** (sección 4.2 del TFM). Implementa un pipeline CI/CD completo que
integra controles de calidad funcional, seguridad y rendimiento, gobernados
mediante *quality gates* automatizados.

La aplicación de prueba es una **API REST de gestión de tareas y proyectos**
(FastAPI + SQLite + JWT) que contiene **defectos sembrados y documentados** para
que cada control del modelo detecte algo real.

---

## 1. Arquitectura del repositorio

```
devsecperops-validation/
├── app/                     API FastAPI (con defectos sembrados documentados)
├── tests/                   Pruebas pytest (cobertura inicial < 80 %)
├── k6/load-test.js          Prueba de carga (Performance Gate)
├── scripts/check_gates.py   Evaluación consolidada de los Quality Gates
├── sonar-project.properties Configuración de SonarQube (SAST + cobertura)
├── .zap/rules.tsv           Reglas del escaneo DAST (OWASP ZAP)
├── k8s/                     Manifiestos de despliegue (Kubernetes)
├── monitoring/              Configuración de Prometheus
├── .github/workflows/       Pipeline DevSecPerOps (flujo operativo, Tabla 15)
├── Dockerfile
├── docker-compose.yml       Entorno local: API + SonarQube + Prometheus + Grafana
└── requirements.txt         (incluye PyYAML 5.3.1 vulnerable, documentado)
```

## 2. Defectos sembrados y gate que disparan

| Defecto | Control | Gate | Archivo |
|---|---|---|---|
| Inyección SQL por concatenación | SonarQube (SAST) | Vulnerability | `app/main.py` (`/tasks/search`) |
| Secreto embebido en código | SonarQube (SAST) | Quality | `app/auth.py` |
| `yaml.load` inseguro | SonarQube (SAST) | Quality | `app/config.py` |
| Dependencia con CVE (PyYAML 5.3.1) | OWASP Dependency-Check | Dependency | `requirements.txt` |
| XSS reflejado / sin cabeceras | OWASP ZAP (DAST) | Vulnerability | `app/main.py` (`/echo`) |
| Endpoint lento (latencia inyectada) | k6 | Performance | `app/main.py` (`/reports`) |
| Cobertura < 80 % | pytest + SonarQube | Coverage | `tests/test_api.py` |

## 3. Requisitos previos

- Docker y Docker Compose
- Python 3.11
- Cuenta de GitHub (para ejecutar el workflow) **o** ejecución local (apartado 5)
- k6 ([instalación](https://k6.io/docs/get-started/installation/))

## 4. Ejecución del pipeline completo en GitHub Actions

1. Crea un repositorio en GitHub y sube este contenido.
2. Levanta un SonarQube accesible (SonarCloud o una instancia propia) y crea el
   proyecto `devsecperops-validation`.
3. En *Settings → Secrets and variables → Actions*, añade los secretos:
   - `SONAR_TOKEN`
   - `SONAR_HOST_URL`
4. Haz `git push` a `main`. El workflow se ejecuta automáticamente.
5. Revisa la pestaña **Actions**: en la **primera ejecución los gates fallan**
   (detección temprana). Descarga los artefactos generados (apartado 6).

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

# 6. DAST con OWASP ZAP (con la API levantada en :8000)
docker run -t ghcr.io/zaproxy/zaproxy zap-baseline.py \
  -t http://host.docker.internal:8000 -J zap-report.json

# 7. Prueba de carga con k6  -> genera k6-summary.json
k6 run --summary-export=k6-summary.json k6/load-test.js

# 8. Evaluación consolidada de los Quality Gates
python scripts/check_gates.py \
  --coverage coverage.xml \
  --dependency reports/dependency-check-report.json \
  --zap zap-report.json \
  --k6 k6-summary.json
```

## 6. DATOS A CAPTURAR Y ENVIARME (para redactar 4.2.3 y 4.2.4)

Para la **primera ejecución (con defectos)** y la **segunda ejecución (tras la
remediación, apartado 7)**, captura y envíame:

**a) Cobertura (Coverage Gate)**
- Porcentaje de cobertura que muestra `pytest --cov` y SonarQube.

**b) SonarQube (SAST / Quality Gate)**
- Nº de *vulnerabilities*, *bugs*, *security hotspots*, *code smells*.
- Estado del Quality Gate (Passed / Failed) — captura de pantalla del panel.

**c) Dependencias (Dependency Gate)**
- Nº de dependencias vulnerables y CVE detectadas (especialmente la de PyYAML).

**d) DAST / OWASP ZAP (Vulnerability Gate)**
- Nº de alertas por nivel de riesgo (High / Medium / Low) y sus nombres.

**e) Rendimiento / k6 (Performance Gate)**
- `http_req_duration` p(95) y p(99), tiempo medio, throughput (req/s) y % errores.

**f) Resultado del pipeline**
- Contenido de `gates-summary.json` y captura del grafo de jobs en GitHub Actions
  (qué etapa bloqueó el pipeline).

> Sugerencia: pega cada valor en una tabla o envíame directamente los archivos
> `coverage.xml`, `dependency-check-report.json`, `zap-report.json`,
> `k6-summary.json` y `gates-summary.json`. Con eso completo el análisis.

## 7. Remediación (segunda ejecución)

Para demostrar el ciclo de mejora y que los gates terminan en verde:

1. `app/auth.py`: leer `SECRET_KEY` de `os.environ`.
2. `app/config.py`: sustituir `yaml.load` por `yaml.safe_load`.
3. `app/main.py` (`/tasks/search`): usar parámetros enlazados en lugar de concatenar.
4. `app/main.py` (`/echo`): escapar la entrada (o eliminar el endcuentro) y añadir
   *middleware* de cabeceras de seguridad.
5. `requirements.txt`: actualizar a `PyYAML>=6.0.1`.
6. `config.yaml`: poner `report_delay_ms: 0`.
7. `tests/test_api.py`: añadir pruebas para `/tasks/search`, `/echo` y `/reports`
   hasta superar el 80 % de cobertura.

Vuelve a ejecutar el pipeline: todos los gates deben pasar y se autoriza el despliegue.
```
