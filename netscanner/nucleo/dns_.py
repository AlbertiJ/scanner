"""Consultas DNS con dnspython, con una caída elegante a `socket` si no está.

Resuelve nombres a IPs y al revés (PTR), y trae los registros más usados:
  A     (IPv4)          NS    (servidores de nombres)
  AAAA  (IPv6)          TXT   (texto: SPF, verificaciones, etc.)
  MX    (correo)        CNAME (alias)
  SOA   (autoridad)     PTR   (inverso: IP → nombre)

Todo devuelve (registros, error): registros es una lista de strings ya
formateados y legibles; error es "" si salió bien.
"""

from __future__ import annotations

import socket

TIPOS = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]

# DNS públicos frecuentes, para ofrecerlos como opción.
SERVIDORES = [
    ("DNS del sistema", ""),
    ("Google (8.8.8.8)", "8.8.8.8"),
    ("Cloudflare (1.1.1.1)", "1.1.1.1"),
    ("Quad9 (9.9.9.9)", "9.9.9.9"),
]


def disponible():
    """True si dnspython está instalado (para los tipos que socket no cubre)."""
    import importlib.util
    return importlib.util.find_spec("dns") is not None


def _formatear(tipo, dato):
    """Convierte un registro de dnspython en un texto legible."""
    if tipo == "MX":
        return f"prioridad {dato.preference:>4}  →  {dato.exchange}"
    if tipo == "SOA":
        return (f"servidor {dato.mname} · admin {dato.rname} · "
                f"serie {dato.serial} · refresco {dato.refresh}s")
    if tipo == "TXT":
        partes = dato.strings if hasattr(dato, "strings") else [dato.to_text()]
        return " ".join(
            t.decode(errors="replace") if isinstance(t, (bytes, bytearray)) else str(t)
            for t in partes
        )
    return dato.to_text()


def consultar(nombre, tipo="A", servidor="", timeout=5):
    """Consulta un registro DNS. Devuelve (registros, error).

    'nombre'   dominio a consultar (o una IP, para el tipo PTR/inverso).
    'tipo'     uno de TIPOS.
    'servidor' opcional: un DNS puntual (ej. '8.8.8.8'); vacío = el del sistema.
    """
    nombre = (nombre or "").strip()
    if not nombre:
        return [], "Escribí un dominio o una IP."
    tipo = (tipo or "A").upper()
    if tipo not in TIPOS:
        return [], f"Tipo de registro no soportado: {tipo}"

    if not disponible():
        return _consultar_socket(nombre, tipo)

    import dns.exception
    import dns.resolver
    import dns.reversename

    r = dns.resolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    servidor = (servidor or "").strip()
    if servidor:
        r.nameservers = [servidor]

    consulta = nombre
    if tipo == "PTR":
        try:
            consulta = str(dns.reversename.from_address(nombre))
        except Exception:
            return [], f"Para una búsqueda inversa (PTR) necesito una IP válida, no '{nombre}'."

    try:
        resp = r.resolve(consulta, tipo)
    except dns.resolver.NXDOMAIN:
        return [], f"No existe el dominio: {nombre}"
    except dns.resolver.NoAnswer:
        return [], f"{nombre} no tiene registros {tipo}."
    except dns.resolver.NoNameservers:
        return [], "Ningún servidor DNS respondió. ¿Hay conexión? ¿El servidor es correcto?"
    except dns.exception.Timeout:
        return [], f"El servidor DNS no respondió en {timeout}s."
    except Exception as e:
        return [], f"Error de DNS: {e}"

    return [_formatear(tipo, d) for d in resp], ""


def _consultar_socket(nombre, tipo):
    """Sin dnspython: resolvemos lo básico (A, AAAA, PTR) con el sistema."""
    try:
        if tipo == "PTR":
            host, _alias, _ips = socket.gethostbyaddr(nombre)
            return [host], "Resuelto con el sistema (instalá dnspython para más detalle)."
        familia = {"A": socket.AF_INET, "AAAA": socket.AF_INET6}.get(tipo, 0)
        infos = socket.getaddrinfo(nombre, None, familia)
        ips = sorted({i[4][0] for i in infos})
        if not ips:
            return [], f"{nombre} no tiene registros {tipo}."
        aviso = "" if tipo in ("A", "AAAA") else (
            f"Sin dnspython solo puedo resolver A/AAAA/PTR; te muestro las IPs de {nombre}. "
            "Instalá dnspython (pip install dnspython) para MX, NS, TXT, etc.")
        return ips, aviso
    except socket.gaierror:
        return [], f"No se pudo resolver '{nombre}'. ¿El nombre existe? ¿Hay conexión?"
    except Exception as e:
        return [], f"Error al resolver: {e}"
