"""Carga de configuración de la aplicación.

REMEDIADO: se utiliza yaml.safe_load, que solo deserializa tipos de datos
básicos y evita la ejecución de código arbitrario asociada a yaml.load.
"""

import os
import yaml


def load_config(path: str = "config.yaml") -> dict:
    if not os.path.exists(path):
        return _default_config()
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh.read())


def _default_config() -> dict:
    return {
        "app_name": "TaskManager API",
        "version": "1.0.0",
        "page_size": 50,
        "report_delay_ms": 0,  # REMEDIADO: sin latencia artificial
    }


CONFIG = load_config()
