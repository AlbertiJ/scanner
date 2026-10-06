"""Integración opcional con nmap, el escáner de referencia.

Si el sistema tiene nmap instalado y la librería python-nmap, se puede pedir un
escaneo más profundo (versiones de servicios, detección de SO). Es opcional: el
resto del programa funciona sin nmap.
"""

from __future__ import annotations


def disponible():
    """(ok, motivo). Verifica la librería y el ejecutable de nmap."""
    try:
        import nmap
    except ImportError:
        return False, "Falta la librería: pip install python-nmap"
    try:
        nmap.PortScanner()
    except nmap.PortScannerError:
        return False, ("nmap no está instalado en el sistema. En Linux: "
                       "'sudo apt install nmap'. En Windows: descargalo de nmap.org.")
    return True, ""


def escanear(objetivo, argumentos="-sV -T4"):
    """Corre nmap sobre un objetivo. Devuelve (resultados, error).

    'argumentos' por defecto detecta versiones de servicios. Detectar SO (-O)
    necesita privilegios de administrador.
    Cada resultado: {ip, puerto, protocolo, estado, servicio, producto, version}.
    """
    ok, motivo = disponible()
    if not ok:
        return [], motivo
    import nmap
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=objetivo, arguments=argumentos)
    except nmap.PortScannerError as e:
        return [], f"nmap falló: {e}"
    except Exception as e:
        return [], f"Error inesperado de nmap: {e}"

    filas = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for puerto in sorted(nm[host][proto].keys()):
                d = nm[host][proto][puerto]
                filas.append({
                    "ip": host, "puerto": puerto, "protocolo": proto,
                    "estado": d.get("state", ""), "servicio": d.get("name", ""),
                    "producto": d.get("product", ""), "version": d.get("version", ""),
                })
    return filas, ""
