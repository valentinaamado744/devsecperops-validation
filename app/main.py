"""TaskManager API - aplicación de validación del modelo DevSecPerOps.

Esta API expone la gestión de usuarios, proyectos y tareas. Incluye, de forma
intencionada y documentada, una serie de defectos controlados que permiten
demostrar que cada control y cada quality gate del modelo DevSecPerOps detecta
algo real:

  * Inyección SQL por concatenación de cadenas .... SAST / Vulnerability Gate
  * Cabeceras de seguridad ausentes ................ DAST / Vulnerability Gate
  * Parámetro reflejado en la respuesta ............ DAST / Vulnerability Gate
  * Endpoint /reports con latencia inyectada ....... k6  / Performance Gate

Los defectos están marcados con el comentario "DEFECTO SEMBRADO".
"""

import time

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import (
    create_access_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.config import CONFIG
from app.database import Base, engine, get_db

Base.metadata.create_all(bind=engine)

app = FastAPI(title=CONFIG.get("app_name", "TaskManager API"))

# Observabilidad: expone /metrics para Prometheus
Instrumentator().instrument(app).expose(app)


def get_current_user(
    authorization: str = Header(default=""), db: Session = Depends(get_db)
) -> models.User:
    token = authorization.replace("Bearer ", "").strip()
    username = decode_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Token inválido o ausente")
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return user

@app.get("/", response_class=HTMLResponse)
def index():
    return """<html><body>
    <h1>TaskManager API</h1>
    <ul>
      <li><a href="/health">health</a></li>
      <li><a href="/docs">docs</a></li>
      <li><a href="/echo?message=hello">echo</a></li>
      <li><a href="/reports">reports</a></li>
    </ul>
    </body></html>"""

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/register", response_model=schemas.UserOut, status_code=201)
def register(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    exists = (
        db.query(models.User)
        .filter(models.User.username == payload.username)
        .first()
    )
    if exists:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    user = models.User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=schemas.Token)
def login(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    user = (
        db.query(models.User)
        .filter(models.User.username == payload.username)
        .first()
    )
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    return schemas.Token(access_token=create_access_token(user.username))


@app.post("/projects", response_model=schemas.ProjectOut, status_code=201)
def create_project(
    payload: schemas.ProjectCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    project = models.Project(
        name=payload.name, description=payload.description, owner_id=user.id
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@app.get("/projects", response_model=list[schemas.ProjectOut])
def list_projects(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    return db.query(models.Project).filter(models.Project.owner_id == user.id).all()


@app.post("/tasks", response_model=schemas.TaskOut, status_code=201)
def create_task(
    payload: schemas.TaskCreate,
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    task = models.Task(
        title=payload.title,
        description=payload.description,
        status=payload.status,
        priority=payload.priority,
        project_id=payload.project_id,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


@app.get("/tasks", response_model=list[schemas.TaskOut])
def list_tasks(
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    return db.query(models.Task).all()


@app.get("/tasks/search")
def search_tasks(q: str, db: Session = Depends(get_db)):
    """Búsqueda de tareas por título.

    DEFECTO SEMBRADO (inyección SQL): la consulta se construye concatenando
    directamente la entrada del usuario. SonarQube lo reporta como vulnerabilidad
    de seguridad (SQL injection). La forma correcta sería usar parámetros enlazados.
    """
    # DEFECTO SEMBRADO: concatenación directa de entrada de usuario
    query = "SELECT id, title, status FROM tasks WHERE title LIKE '%" + q + "%'"
    rows = db.execute(text(query)).fetchall()
    return [{"id": r[0], "title": r[1], "status": r[2]} for r in rows]


@app.get("/echo", response_class=HTMLResponse)
def echo(message: str = ""):
    """Devuelve el mensaje recibido.

    DEFECTO SEMBRADO (XSS reflejado): el parámetro se inserta sin escapar en una
    respuesta HTML. OWASP ZAP lo detecta como Cross-Site Scripting reflejado.
    """
    # DEFECTO SEMBRADO: input reflejado sin sanitizar
    return f"<html><body><h3>Mensaje: {message}</h3></body></html>"


@app.get("/reports")
def reports(db: Session = Depends(get_db)):
    """Genera un informe agregado de tareas.

    DEFECTO SEMBRADO (rendimiento): se inyecta una latencia artificial que
    simula una consulta ineficiente. k6 mide tiempos de respuesta altos y el
    Performance Gate marca el build como fallido si se supera el umbral.
    """
    delay_ms = CONFIG.get("report_delay_ms", 1200)
    time.sleep(delay_ms / 1000.0)  # DEFECTO SEMBRADO: latencia inyectada
    total = db.query(models.Task).count()
    done = db.query(models.Task).filter(models.Task.status == "done").count()
    return {
        "total_tasks": total,
        "done_tasks": done,
        "completion_rate": (done / total) if total else 0,
    }
