"""Descubrimiento de hosts activos en la red.

Dos técnicas, y el programa usa la mejor disponible:

  - PING (sin privilegios): le manda un ping a cada IP del rango. Funciona en
    Windows y Linux sin ser administrador. Da IP y nombre.
  - ARP (con privilegios): pregunta "¿quién tiene esta IP?" a nivel de red
    local. Es más rápido y además devuelve la MAC (y con ella el fabricante),
    pero necesita permisos de administrador y, en Windows, Npcap.

Los resultados se informan de a uno, apenas aparecen, para que la interfaz los
muestre en vivo. Cualquier escaneo se puede cancelar con un threading.Event.
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

from . import fabricante, red


def _ping_ok(ip, timeout=1):
    """Un ping a una IP. Devuelve True si contesta. Multiplataforma."""
    if red.ES_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout + 2)
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def _mac_por_arp_local(ip):
    """Lee la MAC de la tabla ARP del sistema (no requiere privilegios).
    Sirve para ponerle fabricante a un host que ya respondió al ping."""
    try:
        if red.ES_WINDOWS:
            salida = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3).stdout
            for linea in salida.splitlines():
                if ip in linea:
                    for tok in linea.replace("-", ":").split():
                        if tok.count(":") == 5:
                            return tok.upper()
        else:
            salida = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=3).stdout
            partes = salida.split()
            if "lladdr" in partes:
                return partes[partes.index("lladdr") + 1].upper()
    except (subprocess.SubprocessError, OSError, ValueError, IndexError):
        pass
    return ""


def por_ping(rango, al_encontrar=None, cancelar=None, hilos=128, timeout=1):
    """Barre el rango con pings. Devuelve la lista de hosts activos.

    al_encontrar(host_dict)  se llama por cada host que responde (para la UI).
    cancelar                 threading.Event; si se activa, corta el barrido.
    """
    cancelar = cancelar or threading.Event()
    encontrados = []
    lock = threading.Lock()

    def revisar(ip):
        if cancelar.is_set() or not _ping_ok(ip, timeout):
            return
        mac = _mac_por_arp_local(ip)
        host = {"ip": ip, "hostname": _hostname(ip), "mac": mac,
                "fabricante": fabricante.buscar(mac) if mac else "", "metodo": "ping"}
        with lock:
            encontrados.append(host)
        if al_encontrar:
            al_encontrar(host)

    ips = red.hosts_de(rango)
    with ThreadPoolExecutor(max_workers=hilos) as pool:
        pool.map(revisar, ips)

    encontrados.sort(key=lambda h: _clave_ip(h["ip"]))
    return encontrados


def por_arp(rango, al_encontrar=None, cancelar=None, timeout=2):
    """Descubre hosts con ARP usando Scapy. Más rápido y trae la MAC.
    Requiere privilegios de administrador. Devuelve (hosts, error).
    'error' es un texto si no se pudo (sin privilegios, sin Scapy...), o ''.
    """
    cancelar = cancelar or threading.Event()
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        return [], "Scapy no está instalado (pip install scapy)."

    if not red.es_administrador():
        return [], "El escaneo ARP necesita permisos de administrador. " + red.como_elevar()

    try:
        paquete = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=rango)
        respuestas, _ = srp(paquete, timeout=timeout, verbose=0)
    except PermissionError:
        return [], "Sin permisos para sockets crudos. " + red.como_elevar()
    except OSError as e:
        extra = " En Windows hace falta instalar Npcap (npcap.com)." if red.ES_WINDOWS else ""
        return [], f"No se pudo hacer el ARP: {e}.{extra}"

    hosts = []
    for _, r in respuestas:
        if cancelar.is_set():
            break
        mac = r.hwsrc.upper()
        host = {"ip": r.psrc, "hostname": _hostname(r.psrc), "mac": mac,
                "fabricante": fabricante.buscar(mac), "metodo": "arp"}
        hosts.append(host)
        if al_encontrar:
            al_encontrar(host)
    hosts.sort(key=lambda h: _clave_ip(h["ip"]))
    return hosts, ""


def descubrir(rango, al_encontrar=None, cancelar=None):
    """Elige la mejor técnica: ARP si hay privilegios, ping si no.
    Devuelve (hosts, metodo_usado, aviso)."""
    if red.es_administrador():
        hosts, error = por_arp(rango, al_encontrar, cancelar)
        if not error:
            return hosts, "arp", ""
        # Si el ARP falló pese a los privilegios, caemos al ping.
        return por_ping(rango, al_encontrar, cancelar), "ping", error
    hosts = por_ping(rango, al_encontrar, cancelar)
    aviso = ("Escaneo por ping (sin privilegios). Para ver también las MAC y "
             "los fabricantes, ejecutá como administrador. " + red.como_elevar())
    return hosts, "ping", aviso


def _clave_ip(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0
