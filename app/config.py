"""Carga de configuración de la aplicación.

NOTA (defecto sembrado - SAST): se utiliza yaml.load sin Loader seguro,
lo que SonarQube reporta como vulnerabilidad (deserialización insegura).
Sirve para demostrar el control SAST y el Quality Gate del modelo DevSecPerOps.
"""

import os
import yaml


def load_config(path: str = "config.yaml") -> dict:
    if not os.path.exists(path):
        return _default_config()
    with open(path, "r", encoding="utf-8") as fh:
        # DEFECTO SEMBRADO: yaml.load inseguro (debería ser yaml.safe_load)
        return yaml.load(fh.read())  # noqa: S506


def _default_config() -> dict:
    return {
        "app_name": "TaskManager API",
        "version": "1.0.0",
        "page_size": 50,
        "report_delay_ms": 1200,  # latencia inyectada en /reports (defecto de rendimiento)
    }


CONFIG = load_config()
