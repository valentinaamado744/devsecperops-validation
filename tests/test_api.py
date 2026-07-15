"""Pruebas funcionales de la TaskManager API.

REMEDIADO: se añaden pruebas para /tasks/search, /echo y /reports, que en la
primera ejecución quedaban sin cubrir (Coverage Gate por debajo del umbral).
Estas pruebas, además, validan el comportamiento correcto tras remediar la
inyección SQL y el XSS reflejado.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.fixture(scope="module")
def auth_token():
    client.post("/auth/register", json={"username": "tester", "password": "Pass1234"})
    resp = client.post(
        "/auth/login", json={"username": "tester", "password": "Pass1234"}
    )
    return resp.json()["access_token"]


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_and_login(auth_token):
    assert auth_token
    assert isinstance(auth_token, str)


def test_login_invalid_credentials():
    resp = client.post(
        "/auth/login", json={"username": "tester", "password": "wrong"}
    )
    assert resp.status_code == 401


def test_create_project_and_task(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    proj = client.post(
        "/projects",
        json={"name": "TFM", "description": "Proyecto de prueba"},
        headers=headers,
    )
    assert proj.status_code == 201
    project_id = proj.json()["id"]

    task = client.post(
        "/tasks",
        json={"title": "Escribir capítulo 4", "project_id": project_id},
        headers=headers,
    )
    assert task.status_code == 201
    assert task.json()["title"] == "Escribir capítulo 4"


def test_list_tasks_requires_auth():
    resp = client.get("/tasks")
    assert resp.status_code == 401


def test_search_tasks_returns_results(auth_token):
    headers = {"Authorization": f"Bearer {auth_token}"}
    proj = client.post(
        "/projects",
        json={"name": "Búsqueda", "description": "Proyecto para test de búsqueda"},
        headers=headers,
    )
    project_id = proj.json()["id"]
    client.post(
        "/tasks",
        json={"title": "Tarea buscable", "project_id": project_id},
        headers=headers,
    )

    resp = client.get("/tasks/search", params={"q": "buscable"})
    assert resp.status_code == 200
    assert any(t["title"] == "Tarea buscable" for t in resp.json())


def test_search_tasks_sql_injection_attempt_is_safe():
    # Confirma que la remediación (bind parameters) neutraliza el intento de
    # inyección: no debe producirse un error 500, sino una respuesta normal
    # (lista vacía o resultados legítimos).
    resp = client.get("/tasks/search", params={"q": "'"})
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_echo_returns_message():
    resp = client.get("/echo", params={"message": "hola"})
    assert resp.status_code == 200
    assert "hola" in resp.text


def test_echo_escapes_script_tags():
    # Confirma que la remediación (html.escape) neutraliza el XSS reflejado:
    # el payload no debe aparecer sin escapar en la respuesta.
    payload = "<script>alert(1)</script>"
    resp = client.get("/echo", params={"message": payload})
    assert resp.status_code == 200
    assert "<script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_reports_returns_summary():
    resp = client.get("/reports")
    assert resp.status_code == 200
    body = resp.json()
    assert "total_tasks" in body
    assert "done_tasks" in body
    assert "completion_rate" in body


def test_security_headers_present():
    # Confirma que el middleware de cabeceras de seguridad está activo.
    resp = client.get("/health")
    csp = resp.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "object-src 'none'" in csp
    assert resp.headers.get("x-frame-options") == "DENY"
    assert resp.headers.get("x-content-type-options") == "nosniff"
