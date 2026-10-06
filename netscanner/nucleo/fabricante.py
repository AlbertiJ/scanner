"""Identifica el fabricante de un equipo a partir de su dirección MAC.

Los primeros 3 bytes de una MAC (el OUI) los asigna la IEEE a cada fabricante.
Con eso, una MAC como AC:BC:32:11:22:33 se traduce a "Apple".

Dos niveles de búsqueda:
  1. Una tabla chica de fabricantes comunes con nombres lindos (rápida).
  2. La base completa de la IEEE (~40.000 asignaciones), en datos/oui.csv.gz,
     que se carga recién la primera vez que hace falta.

La base viene del repositorio anishalx/netscanner, que a su vez la toma de
https://standards.ieee.org/products-programs/regauth/oui/
"""

from __future__ import annotations

import csv
import gzip
import os
from functools import lru_cache

# Fabricantes frecuentes, con nombres cortos y claros. Se consultan primero.
COMUNES = {
    "00000C": "Cisco", "00156D": "Ubiquiti", "24A43C": "Ubiquiti",
    "488F5A": "MikroTik", "6C3B6B": "MikroTik", "50FA84": "TP-Link",
    "C04A00": "TP-Link", "001B11": "D-Link", "204E7F": "Netgear",
    "001BFC": "ASUS", "485B39": "ASUS", "3CD92B": "HP", "F8BC12": "Dell",
    "001422": "Dell", "00E04C": "Realtek", "0002B3": "Intel",
    "0013E8": "Intel", "001B21": "Intel", "3C970E": "Intel",
    "001A11": "Google", "18B430": "Google/Nest", "74C246": "Amazon",
    "F0272D": "Amazon", "000393": "Apple", "001124": "Apple",
    "001CB3": "Apple", "3C0754": "Apple", "ACBC32": "Apple",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "001132": "Synology", "0011D8": "ASUSTek", "F4F5D8": "Google",
    "5CCF7F": "Espressif (ESP)", "A020A6": "Espressif (ESP)", "246F28": "Espressif (ESP)",
    "001517": "Intel", "00D861": "Micro-Star (MSI)", "8C1645": "Xiaomi",
    "286FB9": "Nokia", "001999": "Motorola", "D0577B": "Samsung", "F0EF86": "Samsung",
}

_RUTA_OUI = os.path.join(os.path.dirname(os.path.dirname(__file__)), "datos", "oui.csv.gz")
_BASE_IEEE = None


def _normalizar(mac):
    """AC:BC:32:11:22:33 -> 'ACBC32' (los primeros 3 bytes en mayúsculas)."""
    limpia = "".join(c for c in str(mac or "") if c.isalnum()).upper()
    return limpia[:6] if len(limpia) >= 6 else ""


def _cargar_base_ieee():
    global _BASE_IEEE
    if _BASE_IEEE is not None:
        return _BASE_IEEE
    _BASE_IEEE = {}
    if not os.path.isfile(_RUTA_OUI):
        return _BASE_IEEE
    try:
        with gzip.open(_RUTA_OUI, "rt", encoding="utf-8", errors="replace") as f:
            for fila in csv.reader(f):
                # columnas: Registry, Assignment(OUI), Organization Name, Address
                if len(fila) >= 3 and len(fila[1]) == 6:
                    _BASE_IEEE[fila[1].upper()] = fila[2].strip().strip('"')
    except (OSError, csv.Error):
        pass
    return _BASE_IEEE


@lru_cache(maxsize=4096)
def buscar(mac):
    """Devuelve el nombre del fabricante, o '' si no se reconoce la MAC."""
    oui = _normalizar(mac)
    if not oui:
        return ""
    if oui in COMUNES:
        return COMUNES[oui]
    nombre = _cargar_base_ieee().get(oui, "")
    # La IEEE guarda nombres largos y legales; los recortamos un poco.
    if len(nombre) > 28:
        nombre = nombre[:27].rstrip(" ,.") + "…"
    return nombre


def cantidad_conocidos():
    """Cuántos fabricantes hay en la base (para diagnóstico)."""
    return len(COMUNES) + len(_cargar_base_ieee())
