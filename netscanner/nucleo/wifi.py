"""Redes WiFi cercanas: escanearlas y, si querés, conectarte a una.

No hay una forma única de hacerlo que sirva en todos lados, así que cada
sistema usa su herramienta:

  - Linux:   'nmcli' (NetworkManager). No necesita ser root y da señal, canal
             y seguridad. Si no está, se intenta con 'iw' (sí necesita root).
  - Windows: 'netsh wlan ...'.
  - macOS:   la utilidad 'airport' (solo escanear).

escanear() devuelve una lista de redes: ssid, señal (0-100), canal, seguridad,
bssid. Si el sistema no tiene WiFi o falta la herramienta, devuelve
(lista_vacía, motivo) explicando por qué.

conectar() usa las mismas herramientas del sistema, como si te conectaras desde
su menú WiFi. Usala solo con redes tuyas, o abiertas y públicas que puedas usar.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import time

from . import red


def escanear():
    """Escanea las redes WiFi visibles. Devuelve (redes, aviso)."""
    if red.ES_WINDOWS:
        return _windows()
    if sys.platform == "darwin":
        return _mac()
    redes, aviso = _linux()
    if not redes and red.en_wsl():
        aviso = ("WSL no ve las placas WiFi de Windows. Para escanear redes WiFi "
                 "usá Windows o un Linux instalado en la máquina.")
    return redes, aviso


def _correr(cmd, timeout=15, err=False):
    """Corre un comando. Devuelve (salida, código); la salida es None si el programa
    no existe. La salida se lee con la codificación real de la consola (en Windows en
    español no es la que usa Python por defecto). Con err=True suma lo que el programa
    escribió como error, que sirve para explicar por qué falló."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        return None, -1
    except (subprocess.SubprocessError, OSError):
        return "", -1
    codificacion = red.codificacion_consola()
    salida = r.stdout.decode(codificacion, errors="replace")
    if err:
        salida += r.stderr.decode(codificacion, errors="replace")
    return salida, r.returncode


def _partir_nmcli(linea):
    """Parte una línea del modo terso de nmcli (-t). Los campos van separados
    por ':' y, dentro de un valor, un ':' o una '\\' vienen escapados con '\\'
    (por eso la BSSID llega como AA\\:BB\\:CC...)."""
    campos, actual, i = [], [], 0
    while i < len(linea):
        c = linea[i]
        if c == "\\" and i + 1 < len(linea):      # el carácter escapado es literal
            actual.append(linea[i + 1])
            i += 2
            continue
        if c == ":":
            campos.append("".join(actual))
            actual = []
        else:
            actual.append(c)
        i += 1
    campos.append("".join(actual))
    return campos


# --------------------------------------------------------------------------
def _linux():
    # nmcli es lo más cómodo: no pide root y da todo formateado.
    salida, codigo = _correr(["nmcli", "-t", "-f", "SSID,SIGNAL,CHAN,SECURITY,BSSID",
                              "device", "wifi", "list", "--rescan", "yes"])
    if salida is not None and codigo == 0:
        redes = []
        for linea in salida.splitlines():
            campos = _partir_nmcli(linea)
            if len(campos) < 4:
                continue
            ssid = campos[0] or "(oculta)"
            redes.append({
                "ssid": ssid,
                "senal": _entero(campos[1]),
                "canal": campos[2],
                "seguridad": campos[3] or "Abierta",
                "bssid": campos[4] if len(campos) > 4 else "",
            })
        return _ordenar(redes), "" if redes else "No se detectaron redes WiFi."
    # nmcli no está, o no anda (NetworkManager apagado, sin placa WiFi):
    # probamos con iw, que necesita root pero no depende de NetworkManager.
    return _linux_iw()


def _linux_iw():
    if not red.es_administrador():
        return [], ("Para escanear WiFi sin NetworkManager (nmcli) hace falta "
                    "'iw' y permisos de administrador. " + red.como_elevar())
    # Buscamos una interfaz wireless.
    salida, _ = _correr(["iw", "dev"])
    if salida is None:
        return [], "No encontré ni 'nmcli' ni 'iw'. Instalá uno de los dos para escanear WiFi."
    m = re.search(r"Interface (\w+)", salida or "")
    if not m:
        return [], "No detecté ninguna interfaz WiFi en este equipo."
    iface = m.group(1)
    salida, codigo = _correr(["iw", "dev", iface, "scan"], timeout=20)
    if codigo != 0 or not salida:
        return [], "El escaneo con 'iw' falló (¿ejecutaste con sudo?)."
    redes = []
    for bloque in salida.split("BSS ")[1:]:
        bssid = bloque[:17].upper()
        ssid = (re.search(r"SSID: (.*)", bloque) or [None, "(oculta)"])[1].strip() or "(oculta)"
        sig = re.search(r"signal: ([\-\d.]+) dBm", bloque)
        senal = _dbm_a_porcentaje(float(sig.group(1))) if sig else 0
        seg = "WPA2/WPA3" if "RSN" in bloque else ("WPA" if "WPA" in bloque else "Abierta")
        canal = re.search(r"(?:primary channel: |DS Parameter set: channel )(\d+)", bloque)
        redes.append({"ssid": ssid, "senal": senal, "canal": canal.group(1) if canal else "",
                      "seguridad": seg, "bssid": bssid})
    return _ordenar(redes), "" if redes else "No se detectaron redes."


# --------------------------------------------------------------------------
_ABIERTAS = ("abierta", "abierto", "open", "offen", "ouvert", "aberta", "aperta")


def es_abierta(seguridad):
    """True si lo que dice la lista de seguridad corresponde a una red sin clave."""
    return (seguridad or "").strip().lower() in _ABIERTAS


def _parsear_netsh(texto):
    """Lee la salida de 'netsh wlan show networks mode=bssid' SIN depender del idioma
    de Windows. No busca palabras como «Autenticación» o «Señal» (que cambian según el
    idioma y la codificación): se guía por la estructura, que es siempre la misma.

        SSID n : nombre
            1.er campo: tipo de red · 2.º: autenticación (la seguridad) · 3.º: cifrado
            BSSID n : mac                 (una por cada punto de acceso de esa red)
                señal (termina en %) · tipo de radio (802.11…) · canal (un número)
    """
    redes, actual, bss = [], None, None
    for linea in texto.splitlines():
        clave, dos_puntos, valor = linea.partition(":")
        if not dos_puntos:
            continue
        clave, valor = clave.strip(), valor.strip()
        if re.fullmatch(r"SSID\s+\d+", clave, re.I):
            actual = {"ssid": valor or "(oculta)", "seguridad": "", "previos": 0, "bss": []}
            redes.append(actual)
            bss = None
        elif actual is None:
            continue
        elif re.fullmatch(r"BSSID\s+\d+", clave, re.I):
            bss = {"bssid": valor.upper(), "senal": 0, "canal": "", "radio": False}
            actual["bss"].append(bss)
        elif bss is None:                       # campos que van antes del primer BSSID
            actual["previos"] += 1
            if actual["previos"] == 2:
                actual["seguridad"] = valor
        elif re.fullmatch(r"\d{1,3}\s*%", valor):
            bss["senal"] = _entero(valor)
        elif re.match(r"802\.11", valor):
            bss["radio"] = True
        elif re.fullmatch(r"\d{1,3}", valor) and (
                re.fullmatch(r"(?i)canal|channel|kanal|canale|kanaal", clave)
                or (bss["radio"] and not bss["canal"])):
            bss["canal"] = valor
    resultado = []
    for r in redes:
        mejor = max(r["bss"], key=lambda b: b["senal"], default=None)   # el punto de acceso más fuerte
        resultado.append({
            "ssid": r["ssid"],
            "senal": mejor["senal"] if mejor else 0,
            "canal": mejor["canal"] if mejor else "",
            "seguridad": "Abierta" if es_abierta(r["seguridad"]) else (r["seguridad"] or "?"),
            "bssid": mejor["bssid"] if mejor else "",
        })
    return resultado


def _windows():
    salida, _ = _correr(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if salida is None:
        return [], "No encontré 'netsh'. ¿Es este un Windows con WiFi?"
    redes = _parsear_netsh(salida)
    if not redes:
        return [], ("Windows no devolvió redes WiFi. Puede que no haya una placa WiFi encendida, "
                    "que el servicio WLAN esté apagado o que falte el permiso de ubicación "
                    "(Configuración → Privacidad y seguridad → Ubicación).")
    return _ordenar(redes), ""


# --------------------------------------------------------------------------
def _mac():
    ruta = ("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/"
            "Current/Resources/airport")
    salida, codigo = _correr([ruta, "-s"])
    if salida is None or codigo != 0 or not salida:
        return [], "No pude usar 'airport' para escanear WiFi en macOS."
    redes = []
    for linea in salida.splitlines()[1:]:
        partes = linea.split()
        if len(partes) >= 3:
            redes.append({"ssid": partes[0], "senal": _dbm_a_porcentaje(float(partes[2])),
                          "canal": partes[3] if len(partes) > 3 else "",
                          "seguridad": "—", "bssid": partes[1].upper()})
    return _ordenar(redes), ""


# --------------------------------------------------------------------------
# Conectarse a una red
# --------------------------------------------------------------------------
_SIGUIENTE = " Para escanear esa red, elegí la placa WiFi en «Interfaces» (Enter)."


def conectar(ssid, clave="", seguridad=""):
    """Se conecta a una red WiFi con las herramientas del propio sistema. Devuelve
    (ok, mensaje). La clave se usa solo para esto: no se guarda ni se muestra.

    Un portal cautivo (la página de «iniciar sesión» de algunas redes abiertas de
    hoteles, bares, aeropuertos) no se puede resolver desde acá: se hace en el navegador.
    """
    ssid = (ssid or "").strip()
    clave = clave or ""
    if not ssid or ssid == "(oculta)":
        return False, "Elegí una red de la lista. Las redes ocultas no se pueden conectar desde acá."
    if any(ord(c) < 32 for c in ssid + clave):
        return False, "El nombre o la clave tienen caracteres que no se pueden usar."
    if es_abierta(seguridad):
        clave = ""
    elif not clave:
        return False, "Esta red tiene clave: escribila en el campo y volvé a tocar Conectar."
    if red.ES_WINDOWS:
        return _conectar_windows(ssid, clave, seguridad)
    if sys.platform == "darwin":
        return False, "En macOS conectate desde el menú WiFi del sistema."
    return _conectar_linux(ssid, clave)


def _ultima_linea(texto):
    lineas = [l.strip() for l in (texto or "").splitlines() if l.strip()]
    return lineas[-1][:160] if lineas else ""


def _conectar_linux(ssid, clave):
    # Cada dato va como un argumento suelto (sin shell): un nombre raro no puede colar comandos.
    cmd = ["nmcli", "--wait", "30", "device", "wifi", "connect", ssid]
    if clave:
        cmd += ["password", clave]
    salida, codigo = _correr(cmd, timeout=45, err=True)
    if salida is None:
        return False, "Para conectarte desde acá hace falta NetworkManager (nmcli). Conectate desde el sistema."
    if codigo == 0:
        return True, "Conectado a %s." % ssid + _SIGUIENTE
    if re.search(r"secrets|password|clave", salida, re.I):
        return False, "No se pudo conectar a %s: la clave parece incorrecta." % ssid
    return False, "No se pudo conectar a %s. %s" % (ssid, _ultima_linea(salida))


def _auth_windows(seguridad):
    """Traduce lo que dice la lista ('WPA2-Personal', 'Abierta'…) al par
    (autenticación, cifrado) de un perfil de Windows. None si no se puede configurar
    desde acá (redes de empresa, WEP)."""
    s = (seguridad or "").lower()
    if es_abierta(s):
        return "open", "none"
    if "enterprise" in s or "empresa" in s or "802.1x" in s:
        return None
    if "wpa3" in s:
        return "WPA3SAE", "AES"
    if "wpa2" in s:
        return "WPA2PSK", "AES"
    if "wpa" in s:
        return "WPAPSK", "TKIP"
    return None


def _perfil_xml(ssid, clave, autenticacion, cifrado, tipo_clave="passPhrase"):
    """El perfil de red que Windows necesita para conectarse (el mismo formato que
    exporta 'netsh wlan export profile')."""
    from xml.sax.saxutils import escape
    nombre = escape(ssid)
    seguridad = ("<authEncryption><authentication>%s</authentication><encryption>%s</encryption>"
                 "<useOneX>false</useOneX></authEncryption>") % (autenticacion, cifrado)
    if autenticacion != "open":
        seguridad += ("<sharedKey><keyType>%s</keyType><protected>false</protected>"
                      "<keyMaterial>%s</keyMaterial></sharedKey>") % (tipo_clave, escape(clave))
    return ('<?xml version="1.0"?>'
            '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">'
            "<name>%s</name><SSIDConfig><SSID><name>%s</name></SSID></SSIDConfig>"
            "<connectionType>ESS</connectionType><connectionMode>manual</connectionMode>"
            "<MSM><security>%s</security></MSM></WLANProfile>") % (nombre, nombre, seguridad)


def _ssid_conectado():
    """El nombre de la red a la que está conectada la placa WiFi ahora ('' si ninguna).
    La línea «SSID : nombre» solo aparece cuando hay conexión, en cualquier idioma."""
    salida, _ = _correr(["netsh", "wlan", "show", "interfaces"])
    m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", salida or "", re.M)
    return m.group(1) if m else ""


def _conectar_windows(ssid, clave, seguridad):
    par = _auth_windows(seguridad)
    if par is None:
        return False, ("Esta red usa una seguridad que no se puede configurar desde acá "
                       "(de empresa o WEP). Conectate desde el menú WiFi de Windows.")
    autenticacion, cifrado = par
    tipo_clave = "passPhrase"
    if autenticacion != "open":
        if re.fullmatch(r"[0-9A-Fa-f]{64}", clave):
            tipo_clave = "networkKey"
        elif not 8 <= len(clave) <= 63:
            return False, "La clave de una red WPA tiene entre 8 y 63 caracteres."
    xml = _perfil_xml(ssid, clave, autenticacion, cifrado, tipo_clave)

    # El perfil lleva la clave en texto claro: vive en un archivo temporal solo unos
    # instantes y se borra apenas Windows lo importa (Windows la guarda cifrada).
    ruta = None
    try:
        fd, ruta = tempfile.mkstemp(prefix="netscanner_wlan_", suffix=".xml")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(xml)
        salida, codigo = _correr(["netsh", "wlan", "add", "profile", "filename=" + ruta, "user=current"],
                                 err=True)
        if salida is None:
            return False, "No encontré 'netsh'. ¿Es este un Windows con WiFi?"
        if codigo != 0:
            return False, "Windows no aceptó los datos de la red. " + _ultima_linea(salida)
    finally:
        if ruta:
            try:
                os.remove(ruta)
            except OSError:
                pass

    salida, codigo = _correr(["netsh", "wlan", "connect", "name=" + ssid, "ssid=" + ssid], err=True)
    if codigo != 0:
        return False, "Windows no pudo iniciar la conexión. " + _ultima_linea(salida)
    for _ in range(15):                          # conectar es asíncrono: esperamos a verla
        time.sleep(1)
        if _ssid_conectado() == ssid:
            return True, "Conectado a %s." % ssid + _SIGUIENTE
    return False, "No se pudo conectar a %s. Revisá la clave y que la señal sea buena." % ssid


# --------------------------------------------------------------------------
def _entero(txt):
    try:
        return max(0, min(100, int(re.sub(r"[^\d\-]", "", txt or "0"))))
    except ValueError:
        return 0


def _dbm_a_porcentaje(dbm):
    """Convierte la señal en dBm (-30 fuerte, -90 débil) a un 0-100 aproximado."""
    return max(0, min(100, int(2 * (dbm + 100))))


def _ordenar(redes):
    return sorted(redes, key=lambda r: -r["senal"])
