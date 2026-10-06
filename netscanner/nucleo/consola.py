"""Comandos de consola para descubrimiento de red, en un catálogo SEGURO.

En vez de una terminal abierta (que sería una puerta directa a la inyección de
comandos), esto es un catálogo FIJO de comandos conocidos. El usuario elige uno
de una lista; nunca escribe el comando en sí.

Tres barreras contra la inyección de comandos (defensa en profundidad):
  1. El nombre del programa sale de este catálogo, no del usuario.
  2. Se ejecuta con `subprocess.run(lista, shell=False)`: sin shell de por
     medio, el objetivo va como UN argumento suelto, nunca concatenado a una
     línea de shell. Aunque alguien escriba '8.8.8.8; rm -rf ~', eso le llega a
     `ping` como un solo texto inválido, no como dos comandos.
  3. Los comandos que necesitan un objetivo lo validan (IP o nombre de host)
     antes de correr; se rechaza cualquier cosa con metacaracteres de shell.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess

from . import red

# Un nombre de host razonable: letras, números, guiones y puntos. Nada de
# espacios ni ';', '|', '&', '$', backticks, etc. Esta validación por sí sola ya
# frena la inyección; igual usamos shell=False y lista de argumentos como red
# de contención real.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)"
    r"([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def objetivo_valido(texto):
    """True si 'texto' es una IP o un nombre de host válido. Rechaza cualquier
    cosa con metacaracteres de shell (';', '|', '&', espacios, etc.)."""
    texto = (texto or "").strip()
    if not texto:
        return False
    try:
        ipaddress.ip_address(texto)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME.match(texto))


def _catalogo_windows():
    return [
        {"id": "arp", "etiqueta": "Tabla ARP (arp -a)", "programa": "arp",
         "desc": "Equipos que tu máquina ya vio en la red local (IP ↔ MAC).",
         "objetivo": False, "construir": lambda o: ["arp", "-a"]},
        {"id": "rutas", "etiqueta": "Tabla de ruteo (route print)", "programa": "route",
         "desc": "Por dónde sale el tráfico hacia cada red.",
         "objetivo": False, "construir": lambda o: ["route", "print"]},
        {"id": "interfaces", "etiqueta": "Config. IP (ipconfig /all)", "programa": "ipconfig",
         "desc": "Tus interfaces, IPs, DNS y puerta de enlace.",
         "objetivo": False, "construir": lambda o: ["ipconfig", "/all"]},
        {"id": "conexiones", "etiqueta": "Conexiones activas (netstat -ano)", "programa": "netstat",
         "desc": "Puertos abiertos y conexiones, con el PID de cada una.",
         "objetivo": False, "construir": lambda o: ["netstat", "-ano"]},
        {"id": "ping", "etiqueta": "Ping (ping -n 4)", "programa": "ping",
         "desc": "¿Responde el objetivo? Mide la latencia.",
         "objetivo": True, "construir": lambda o: ["ping", "-n", "4", o]},
        {"id": "traceroute", "etiqueta": "Traceroute (tracert)", "programa": "tracert",
         "desc": "El camino de saltos hasta el objetivo.",
         "objetivo": True, "construir": lambda o: ["tracert", "-d", o]},
        {"id": "nslookup", "etiqueta": "nslookup", "programa": "nslookup",
         "desc": "Resolución DNS del nombre/IP con el servidor del sistema.",
         "objetivo": True, "construir": lambda o: ["nslookup", o]},
    ]


def _catalogo_unix():
    # Preferimos las herramientas modernas ('ip', 'ss'); si no están, caemos a
    # las clásicas ('arp', 'route', 'ifconfig', 'netstat').
    tiene_ip = shutil.which("ip") is not None
    tiene_ss = shutil.which("ss") is not None
    return [
        {"id": "arp", "etiqueta": "Tabla ARP / vecinos", "programa": "ip" if tiene_ip else "arp",
         "desc": "Equipos que tu máquina ya vio en la red local (IP ↔ MAC).",
         "objetivo": False, "construir": (lambda o: ["ip", "neigh"]) if tiene_ip else (lambda o: ["arp", "-a"])},
        {"id": "rutas", "etiqueta": "Tabla de ruteo", "programa": "ip" if tiene_ip else "route",
         "desc": "Por dónde sale el tráfico hacia cada red.",
         "objetivo": False, "construir": (lambda o: ["ip", "route"]) if tiene_ip else (lambda o: ["route", "-n"])},
        {"id": "interfaces", "etiqueta": "Interfaces e IPs", "programa": "ip" if tiene_ip else "ifconfig",
         "desc": "Tus interfaces, IPs y estado.",
         "objetivo": False, "construir": (lambda o: ["ip", "addr"]) if tiene_ip else (lambda o: ["ifconfig"])},
        {"id": "conexiones", "etiqueta": "Conexiones activas", "programa": "ss" if tiene_ss else "netstat",
         "desc": "Puertos abiertos y conexiones (TCP/UDP), con el proceso.",
         "objetivo": False, "construir": (lambda o: ["ss", "-tunap"]) if tiene_ss else (lambda o: ["netstat", "-tunap"])},
        {"id": "ping", "etiqueta": "Ping (-c 4)", "programa": "ping",
         "desc": "¿Responde el objetivo? Mide la latencia.",
         "objetivo": True, "construir": lambda o: ["ping", "-c", "4", o]},
        {"id": "traceroute", "etiqueta": "Traceroute", "programa": "traceroute",
         "desc": "El camino de saltos hasta el objetivo.",
         "objetivo": True, "construir": lambda o: ["traceroute", o]},
        {"id": "nslookup", "etiqueta": "nslookup", "programa": "nslookup",
         "desc": "Resolución DNS del nombre/IP con el servidor del sistema.",
         "objetivo": True, "construir": lambda o: ["nslookup", o]},
        {"id": "dig", "etiqueta": "dig", "programa": "dig",
         "desc": "Consulta DNS detallada (registros y tiempos).",
         "objetivo": True, "construir": lambda o: ["dig", o]},
    ]


def catalogo():
    """Lista de comandos para este sistema operativo. A cada uno le agrega
    `disponible` (True si el ejecutable está instalado)."""
    base = _catalogo_windows() if red.ES_WINDOWS else _catalogo_unix()
    for c in base:
        c["disponible"] = shutil.which(c["programa"]) is not None
    return base


def buscar(id_comando):
    """Devuelve la entrada del catálogo con ese id, o None."""
    return next((c for c in catalogo() if c["id"] == id_comando), None)


def ejecutar(id_comando, objetivo="", timeout=20):
    """Corre un comando del catálogo por su id. Devuelve (salida, error).

    Nunca se interpreta texto como shell: se busca el comando en el catálogo,
    se valida el objetivo si hace falta, y se ejecuta con lista de argumentos y
    `shell=False`. Así no hay inyección de comandos posible.
    """
    entrada = buscar(id_comando)
    if entrada is None:
        return "", f"Comando desconocido: {id_comando}"
    if not entrada["disponible"]:
        return "", (f"'{entrada['programa']}' no está instalado en este sistema. "
                    "Instalalo o probá otro comando de la lista.")
    objetivo = (objetivo or "").strip()
    if entrada["objetivo"]:
        if not objetivo_valido(objetivo):
            return "", (f"Objetivo inválido: '{objetivo}'. Poné una IP "
                        "(ej. 192.168.1.1) o un nombre de host (ej. ejemplo.com). "
                        "No se aceptan símbolos ni espacios.")
    elif objetivo:
        # Este comando no usa objetivo; lo ignoramos en vez de arriesgar algo raro.
        objetivo = ""

    argv = entrada["construir"](objetivo)
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, shell=False)
    except FileNotFoundError:
        return "", f"No se encontró el programa '{argv[0]}'."
    except subprocess.TimeoutExpired:
        return "", f"El comando tardó más de {timeout}s y se canceló."
    except Exception as e:   # cualquier fallo del SO al lanzar el proceso
        return "", f"No se pudo ejecutar: {e}"

    # La salida se lee con la codificación real de la consola: en Windows en español no es
    # la que Python usa por defecto, y «Dirección» se veía «Direcci¢n».
    cod = red.codificacion_consola()
    salida = (proc.stdout or b"").decode(cod, errors="replace")
    if proc.returncode != 0 and proc.stderr:
        salida += ("\n" if salida else "") + proc.stderr.decode(cod, errors="replace")
    return salida.strip(), ""
