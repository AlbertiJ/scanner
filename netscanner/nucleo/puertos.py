"""Escaneo de puertos TCP, captura de banners y una estimación del sistema
operativo. Todo por conexión TCP común: no necesita privilegios y anda igual
en Windows y Linux.
"""

from __future__ import annotations

import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

from . import red

# Puertos frecuentes con el nombre de su servicio.
COMUNES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "Submission", 631: "IPP", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2375: "Docker", 3000: "Dev/Grafana", 3306: "MySQL",
    3389: "RDP", 5060: "SIP", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
    6379: "Redis", 6443: "K8s API", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9090: "Prometheus", 9200: "Elasticsearch", 27017: "MongoDB",
}


def _rango_puertos(modo):
    if modo == "comunes":
        return sorted(COMUNES.keys())
    if modo == "1-1024":
        return list(range(1, 1025))
    if modo == "1-10000":
        return list(range(1, 10001))
    return list(range(1, 65536))   # completo


def _abierto(ip, puerto, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, puerto)) == 0
    except OSError:
        return False
    finally:
        s.close()


def banner(ip, puerto, timeout=1.5):
    """Intenta leer el cartel de presentación del servicio (versión, etc.)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, puerto))
        if puerto in (80, 8080, 8443, 8888, 3000, 9090):
            s.send(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode())
        elif puerto not in (21, 22, 25, 110, 143):   # estos mandan banner solos
            s.send(b"\r\n")
        datos = s.recv(256).decode("utf-8", errors="ignore")
        return " ".join(datos.split())[:120]
    except OSError:
        return ""
    finally:
        s.close()


def escanear(ip, modo="comunes", con_banner=True, al_encontrar=None,
             cancelar=None, hilos=200, timeout=0.6):
    """Escanea los puertos de un host. Devuelve la lista de puertos abiertos,
    ordenada. Informa cada puerto apenas lo encuentra (al_encontrar)."""
    cancelar = cancelar or threading.Event()
    abiertos = []
    lock = threading.Lock()

    def revisar(puerto):
        if cancelar.is_set() or not _abierto(ip, puerto, timeout):
            return
        dato = {"puerto": puerto, "servicio": COMUNES.get(puerto, "?"),
                "banner": banner(ip, puerto) if con_banner else ""}
        with lock:
            abiertos.append(dato)
        if al_encontrar:
            al_encontrar(dato)

    with ThreadPoolExecutor(max_workers=hilos) as pool:
        pool.map(revisar, _rango_puertos(modo))

    abiertos.sort(key=lambda d: d["puerto"])
    return abiertos


def estimar_so(ip):
    """Adivina el sistema operativo por el TTL de la respuesta de un ping.
    Es una pista, no una certeza: Linux/Android salen con TTL 64, Windows 128,
    equipos de red (routers) 255. No necesita privilegios."""
    if red.ES_WINDOWS:
        cmd = ["ping", "-n", "1", ip]
    else:
        cmd = ["ping", "-c", "1", ip]
    try:
        salida = subprocess.run(cmd, capture_output=True, text=True, timeout=4).stdout.lower()
    except (subprocess.SubprocessError, OSError):
        return "desconocido", 0
    import re
    m = re.search(r"ttl[=\s]+(\d+)", salida)
    if not m:
        return "desconocido", 0
    ttl = int(m.group(1))
    if ttl <= 64:
        return "Linux / Android / Unix", ttl
    if ttl <= 128:
        return "Windows", ttl
    return "Equipo de red (router/switch)", ttl
