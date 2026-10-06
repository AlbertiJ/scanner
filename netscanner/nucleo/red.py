"""Funciones de red de base: IP local, rango, interfaces y privilegios.

Todo esto es multiplataforma (Windows y Linux) y no necesita permisos de
administrador. Las partes que sí los necesitan (ARP, sniffing) están en sus
propios módulos y avisan cuando faltan.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import sys

ES_WINDOWS = sys.platform.startswith("win")


def ip_local():
    """La IP con la que esta máquina sale a la red. No abre ninguna conexión
    real: solo le pregunta al sistema qué ruta usaría para llegar a internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def rango_local(ip=None, prefijo=24):
    """Deduce el rango de la red local a partir de una IP. Por defecto /24
    (256 direcciones), que es lo típico de una red hogareña o de oficina."""
    ip = ip or ip_local()
    try:
        red = ipaddress.ip_interface(f"{ip}/{prefijo}").network
        return str(red)
    except ValueError:
        partes = ip.split(".")
        return f"{partes[0]}.{partes[1]}.{partes[2]}.0/24"


def hosts_de(rango):
    """Lista de IPs de un rango CIDR (ej. '192.168.1.0/24'), sin la de red ni
    la de broadcast. Lanza ValueError si el rango es inválido."""
    red = ipaddress.ip_network(rango, strict=False)
    return [str(h) for h in red.hosts()]


def es_administrador():
    """True si el programa corre con permisos de administrador/root. Varias
    funciones (ARP, sniffing, algunos WiFi) los necesitan."""
    if ES_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def codificacion_consola():
    """Con qué codificación escriben su salida las herramientas de consola (netsh,
    ipconfig, ping…). En Windows es la página de códigos OEM (en español, la 850) y no
    la que Python usa por defecto (la 1252): por eso «Autenticación» llegaba como
    «Autenticaci¢n». En Linux y macOS es UTF-8."""
    if ES_WINDOWS:
        try:
            import ctypes
            return "cp%d" % ctypes.windll.kernel32.GetOEMCP()
        except Exception:
            return "cp850"
    return "utf-8"


_PROC_VERSION = "/proc/version"


def en_wsl():
    """True si el programa corre dentro de WSL (Linux sobre Windows). Ahí la red
    que se ve suele ser la virtual de WSL y no la de tu casa; sirve para avisarlo."""
    if ES_WINDOWS:
        return False
    try:
        with open(_PROC_VERSION, encoding="utf-8", errors="ignore") as f:
            return "microsoft" in f.read().lower()      # WSL1 y WSL2 lo dicen ahí
    except OSError:
        return False


def como_elevar():
    """Texto de ayuda para volver a lanzar el programa con permisos."""
    if ES_WINDOWS:
        return ("Cerrá el programa, hacé clic derecho en la terminal (o en el "
                "acceso directo) y elegí «Ejecutar como administrador».")
    return "Volvé a lanzarlo con sudo, por ejemplo:  sudo ./iniciar.sh"


def como_elevar_corto():
    """Lo mismo que como_elevar(), en pocas palabras, para avisos de una línea."""
    return "ejecutá como administrador" if ES_WINDOWS else "sudo ./iniciar.sh"


def interfaces():
    """Lista las interfaces de red de la máquina, con su IP, MAC y estado.

    Usa psutil, que funciona igual en Windows y Linux. Devuelve una lista de
    diccionarios: nombre, ipv4, mac, activa, es_loopback.
    """
    import psutil

    direcciones = psutil.net_if_addrs()
    estados = psutil.net_if_stats()
    salida = []
    for nombre, addrs in direcciones.items():
        ipv4, ipv6, mac = "", "", ""
        for a in addrs:
            if a.family == socket.AF_INET:
                ipv4 = a.address
            elif a.family == socket.AF_INET6:
                dir6 = (a.address or "").split("%")[0]     # sin la zona (%eth0)
                if not ipv6 or not dir6.lower().startswith("fe80"):
                    ipv6 = dir6                            # preferimos una global a la link-local
            elif getattr(a, "family", None) == getattr(psutil, "AF_LINK", None) or \
                    (hasattr(a, "family") and a.family.name == "AF_LINK"):
                mac = (a.address or "").upper()
        st = estados.get(nombre)
        salida.append({
            "nombre": nombre,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "mac": mac,
            "activa": bool(st and st.isup),
            "velocidad": st.speed if st else 0,   # Mbps (0 = desconocida)
            "es_loopback": ipv4.startswith("127.") or nombre.lower().startswith("lo"),
        })
    # Primero las activas con IP, después el resto.
    salida.sort(key=lambda i: (not (i["activa"] and i["ipv4"]), i["es_loopback"], i["nombre"]))
    return salida


def interfaz_activa():
    """La interfaz por la que sale el tráfico ahora mismo (la que tiene la IP
    local). Sirve como interfaz por defecto para escanear."""
    mi_ip = ip_local()
    for i in interfaces():
        if i["ipv4"] == mi_ip:
            return i
    activas = [i for i in interfaces() if i["activa"] and i["ipv4"] and not i["es_loopback"]]
    return activas[0] if activas else None
