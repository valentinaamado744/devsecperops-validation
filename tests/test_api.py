"""Pruebas funcionales de la TaskManager API.

La cobertura es intencionadamente parcial (no se prueban /tasks/search, /echo
ni /reports) para que, en la primera ejecución, la cobertura quede por debajo
del umbral del 80 % y el Coverage Gate del modelo DevSecPerOps se dispare.
Tras la remediación se añaden pruebas para superar el umbral.
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
