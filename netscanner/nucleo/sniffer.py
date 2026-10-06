"""Captura de paquetes en vivo (sniffing) con Scapy.

Muestra el tráfico que pasa por la interfaz: TCP, UDP, ICMP, ICMP6 y ARP, con
origen, destino y un resumen. También reconoce los DNS que viajan sin cifrar
(consultas y respuestas). La captura se puede pausar y reanudar sin perder lo
ya capturado. Necesita permisos de administrador y, en Windows, Npcap
(npcap.com). Corre en un hilo aparte para no congelar la interfaz, y se frena
cuando se le pide.
"""

from __future__ import annotations

import threading
import time

from . import red

# Códigos de respuesta DNS que vale la pena mostrar. Muchos «no existe»
# seguidos pueden delatar un programa malicioso que prueba dominios al azar.
RCODES = {1: "error de formato", 2: "falló el servidor", 3: "no existe",
          4: "no implementado", 5: "rechazado"}


def _texto_dns(valor):
    """Convierte un dato de DNS (bytes, lista, texto) en un texto legible."""
    if isinstance(valor, (bytes, bytearray)):
        valor = valor.decode("utf-8", errors="replace")
    elif isinstance(valor, (list, tuple)):
        valor = " ".join(_texto_dns(v) for v in valor)
    texto = str(valor).rstrip(".")
    return "".join(c if c.isprintable() else "·" for c in texto)


def extraer_dns(paquete):
    """Si el paquete lleva DNS devuelve un dict, y si no, None.

    El dict trae: qr ('consulta' o 'respuesta'), nombre, tipo (A, AAAA, MX…) y
    respuestas (lista de textos; vacía en las consultas). Solo se ven los DNS
    sin cifrar (puerto 53 y mDNS): DNS sobre HTTPS o TLS viaja cifrado.
    """
    try:
        from scapy.layers.dns import DNS, dnstypes
        if not paquete.haslayer(DNS):
            return None
        d = paquete[DNS]
        if not d.qdcount or d.qd is None:
            return None
        pregunta = d.qd[0]              # en scapy nuevo qd es una lista; en el viejo, un paquete
        respuesta = d.qr == 1
        respuestas = []
        if respuesta:
            for i in range(d.ancount or 0):
                try:
                    respuestas.append(_texto_dns(d.an[i].rdata))
                except (IndexError, TypeError, AttributeError):
                    break
            if not respuestas and d.rcode:
                respuestas = ["(%s)" % RCODES.get(d.rcode, "error %d" % d.rcode)]
        return {"qr": "respuesta" if respuesta else "consulta",
                "nombre": _texto_dns(pregunta.qname),
                "tipo": dnstypes.get(pregunta.qtype, str(pregunta.qtype)),
                "respuestas": respuestas}
    except Exception:        # un paquete raro no debe frenar la captura
        return None


class Sniffer:
    """Captura paquetes y llama a `al_paquete(dict)` por cada uno.

    Cada paquete se resume en: hora, protocolo, origen, destino, longitud, un
    detalle (puertos, tipo de ICMP, etc.) y, si es un DNS, sus datos (dns).
    Lleva la cuenta por protocolo. Mientras está en pausa no registra nada.
    """

    def __init__(self, al_paquete=None):
        self.al_paquete = al_paquete
        self._hilo = None
        self._parar = threading.Event()
        self._pausa = threading.Event()
        self.conteo = {"TCP": 0, "UDP": 0, "ICMP": 0, "ICMP6": 0, "ARP": 0, "Otro": 0}
        self.total = 0
        self.error = ""

    @staticmethod
    def disponible():
        """(ok, motivo). ok=True si se puede capturar; si no, el motivo."""
        import importlib.util
        if importlib.util.find_spec("scapy") is None:
            return False, "Scapy no está instalado (pip install scapy)."
        if not red.es_administrador():
            return False, "La captura necesita permisos de administrador. " + red.como_elevar()
        if red.ES_WINDOWS:
            return True, "En Windows la captura necesita Npcap instalado (npcap.com)."
        return True, ""

    def _resumir(self, paquete):
        from scapy.all import ARP, ICMP, IP, TCP, UDP
        try:
            from scapy.layers.inet6 import IPv6, _ICMPv6
        except Exception:
            IPv6 = _ICMPv6 = None
        info = {"hora": time.strftime("%H:%M:%S"), "proto": "Otro",
                "origen": "", "destino": "", "long": len(paquete), "detalle": ""}
        if paquete.haslayer(ARP):
            a = paquete[ARP]
            info.update(proto="ARP", origen=a.psrc, destino=a.pdst,
                        detalle="¿quién tiene %s? → %s" % (a.pdst, a.psrc))
        elif paquete.haslayer(IP):
            ip = paquete[IP]
            info["origen"], info["destino"] = ip.src, ip.dst
            if paquete.haslayer(TCP):
                t = paquete[TCP]
                info.update(proto="TCP", detalle="%d → %d  [%s]" % (t.sport, t.dport, t.flags))
            elif paquete.haslayer(UDP):
                u = paquete[UDP]
                info.update(proto="UDP", detalle="%d → %d" % (u.sport, u.dport))
            elif paquete.haslayer(ICMP):
                info.update(proto="ICMP", detalle="tipo %s" % paquete[ICMP].type)
        elif IPv6 is not None and paquete.haslayer(IPv6):
            ip6 = paquete[IPv6]
            info["origen"], info["destino"] = ip6.src, ip6.dst
            if paquete.haslayer(TCP):
                t = paquete[TCP]
                info.update(proto="TCP", detalle="%d → %d  [%s]" % (t.sport, t.dport, t.flags))
            elif paquete.haslayer(UDP):
                u = paquete[UDP]
                info.update(proto="UDP", detalle="%d → %d" % (u.sport, u.dport))
            elif _ICMPv6 is None or any(issubclass(c, _ICMPv6) for c in paquete.layers()):
                # ICMPv6 en sus formas: echo, Neighbor Discovery, MLD, etc.
                info.update(proto="ICMP6", detalle=paquete.lastlayer().name)

        dns = extraer_dns(paquete)
        info["dns"] = dns
        if dns:
            resumen = "DNS %s %s %s" % (dns["qr"], dns["tipo"], dns["nombre"])
            if dns["respuestas"]:
                resumen += " → " + ", ".join(dns["respuestas"][:3])
            info["detalle"] = (info["detalle"] + "  " + resumen).strip()
        return info

    def _capturar(self, interfaz, filtro):
        from scapy.all import sniff
        try:
            sniff(iface=interfaz, filter=filtro or None, store=False,
                  stop_filter=lambda _p: self._parar.is_set(),
                  prn=self._procesar)
        except Exception as e:   # scapy lanza distintos errores según el SO
            mensaje = str(e)
            if "not found" in mensaje.lower() or "no such device" in mensaje.lower():
                extra = " Elegí otra placa en el selector."       # el problema es la placa, no los permisos
            elif red.ES_WINDOWS:
                extra = " ¿Está instalado Npcap?"
            else:
                extra = " ¿Ejecutaste con sudo?"
            self.error = mensaje + extra

    def _procesar(self, paquete):
        if self._parar.is_set() or self._pausa.is_set():
            return
        info = self._resumir(paquete)
        self.conteo[info["proto"]] = self.conteo.get(info["proto"], 0) + 1
        self.total += 1
        if self.al_paquete:
            self.al_paquete(info)

    def arrancar(self, interfaz=None, filtro=""):
        """Empieza a capturar en un hilo. 'filtro' es sintaxis BPF (ej. 'tcp
        port 80'), opcional."""
        ok, motivo = self.disponible()
        if not ok:
            self.error = motivo
            return False
        self._parar.clear()
        self._pausa.clear()
        self._hilo = threading.Thread(target=self._capturar, args=(interfaz, filtro), daemon=True)
        self._hilo.start()
        return True

    def pausar(self):
        """La captura sigue viva pero deja de registrar paquetes."""
        self._pausa.set()

    def reanudar(self):
        self._pausa.clear()

    @property
    def pausado(self):
        return self._pausa.is_set()

    def frenar(self):
        """Pide frenar. Scapy solo se entera cuando llega el próximo paquete,
        así que no esperamos al hilo: queda dormido, ignora todo y termina solo."""
        self._parar.set()
        if self._hilo:
            self._hilo.join(timeout=0.3)

    @property
    def detenido(self):
        return self._parar.is_set()

    @property
    def corriendo(self):
        """True mientras la captura está activa (o en pausa). Vale False apenas
        se pide frenar, aunque el hilo tarde en morir en una red tranquila."""
        return (self._hilo is not None and self._hilo.is_alive()
                and not self._parar.is_set())
