"""Guardar resultados (JSON o texto) y llevar un historial de escaneos.

Todo se guarda en la carpeta 'resultados' junto al programa. El historial es
un archivo JSONL (una línea por escaneo) con qué se hizo, cuándo y un resumen.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime

CARPETA = os.path.join(os.getcwd(), "resultados")
HISTORIAL = os.path.join(CARPETA, "historial.jsonl")


def _a_nombre_del_usuario(ruta):
    """Con sudo, lo que se crea nace de root y después tu usuario no podría
    borrarlo ni guardar nuevos resultados. Lo dejamos a nombre de quien lanzó sudo."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    try:
        os.chown(ruta, int(uid), int(gid or uid))
    except (OSError, ValueError):
        pass


def _asegurar_carpeta():
    os.makedirs(CARPETA, exist_ok=True)
    _a_nombre_del_usuario(CARPETA)


def _sello():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def guardar_json(tipo, objetivo, datos):
    """Guarda 'datos' como JSON. Devuelve la ruta del archivo."""
    _asegurar_carpeta()
    ruta = os.path.join(CARPETA, f"{tipo}-{_sello()}.json")
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump({"tipo": tipo, "objetivo": objetivo,
                   "fecha": datetime.now().isoformat(timespec="seconds"),
                   "resultados": datos}, f, ensure_ascii=False, indent=2)
    _a_nombre_del_usuario(ruta)
    return ruta


def guardar_txt(tipo, objetivo, lineas):
    """Guarda una lista de líneas de texto. Devuelve la ruta."""
    _asegurar_carpeta()
    ruta = os.path.join(CARPETA, f"{tipo}-{_sello()}.txt")
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(f"NetScanner — {tipo}\n")
        f.write(f"Objetivo: {objetivo}\n")
        f.write(f"Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        f.write("\n".join(str(l) for l in lineas) + "\n")
    _a_nombre_del_usuario(ruta)
    return ruta


def guardar_csv(tipo, objetivo, datos):
    """Guarda 'datos' como CSV. Devuelve la ruta.

    Si son diccionarios (IPs, puertos, paquetes), arma columnas con encabezado.
    Si son textos sueltos (DNS, consola), una columna por línea.
    """
    _asegurar_carpeta()
    ruta = os.path.join(CARPETA, f"{tipo}-{_sello()}.csv")
    with open(ruta, "w", encoding="utf-8", newline="") as f:
        if datos and isinstance(datos[0], dict):
            campos = list(datos[0].keys())
            w = csv.DictWriter(f, fieldnames=campos)
            w.writeheader()
            for d in datos:
                w.writerow({k: d.get(k, "") for k in campos})
        else:
            w = csv.writer(f)
            w.writerow([tipo])
            for d in datos:
                w.writerow([d])
    _a_nombre_del_usuario(ruta)
    return ruta


def anotar_historial(tipo, objetivo, resumen):
    """Suma una línea al historial. No falla nunca (es secundario)."""
    try:
        _asegurar_carpeta()
        with open(HISTORIAL, "a", encoding="utf-8") as f:
            f.write(json.dumps({"fecha": datetime.now().isoformat(timespec="seconds"),
                                "tipo": tipo, "objetivo": objetivo, "resumen": resumen},
                               ensure_ascii=False) + "\n")
        _a_nombre_del_usuario(HISTORIAL)
    except OSError:
        pass


def leer_historial(maximo=50):
    """Últimas entradas del historial, de la más nueva a la más vieja."""
    if not os.path.isfile(HISTORIAL):
        return []
    filas = []
    try:
        with open(HISTORIAL, encoding="utf-8") as f:
            for linea in f:
                linea = linea.strip()
                if linea:
                    try:
                        filas.append(json.loads(linea))
                    except json.JSONDecodeError:
                        pass
    except OSError:
        return []
    return list(reversed(filas))[:maximo]
