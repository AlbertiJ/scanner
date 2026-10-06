"""Pruebas de los motores de escaneo. No tocan la red real: verifican la
lógica pura (rangos, fabricantes, parseo, degradación sin privilegios)."""

import asyncio
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netscanner.nucleo import (consola, dns_, exportar, fabricante,   # noqa: E402
                               puertos, red, wifi)


class Red(unittest.TestCase):
    def test_rango_local(self):
        self.assertEqual(red.rango_local("192.168.1.57"), "192.168.1.0/24")
        self.assertEqual(red.rango_local("10.0.0.5", prefijo=16), "10.0.0.0/16")

    def test_hosts_de(self):
        hosts = red.hosts_de("192.168.1.0/30")   # .1 y .2 (sin red ni broadcast)
        self.assertEqual(hosts, ["192.168.1.1", "192.168.1.2"])

    def test_rango_invalido(self):
        with self.assertRaises(ValueError):
            red.hosts_de("no-es-un-rango")

    def test_interfaces_devuelve_algo(self):
        ifs = red.interfaces()
        self.assertTrue(any(i["ipv4"] for i in ifs), "debería haber al menos una interfaz con IP")

    def test_interfaces_tiene_ipv6(self):
        for i in red.interfaces():
            self.assertIn("ipv6", i)   # la clave siempre está (aunque sea "")


class Fabricante(unittest.TestCase):
    def test_builtin(self):
        self.assertEqual(fabricante.buscar("B8:27:EB:11:22:33"), "Raspberry Pi")
        self.assertEqual(fabricante.buscar("ac:bc:32:00:00:00"), "Apple")   # minúsculas

    def test_base_ieee(self):
        # 28:6F:B9 está en la base IEEE (Nokia), no en la tabla chica.
        self.assertIn("Nokia", fabricante.buscar("28:6F:B9:00:00:00"))

    def test_mac_desconocida_o_vacia(self):
        self.assertEqual(fabricante.buscar(""), "")
        self.assertEqual(fabricante.buscar("xx"), "")

    def test_base_grande(self):
        self.assertGreater(fabricante.cantidad_conocidos(), 10000)


class Puertos(unittest.TestCase):
    def test_servicios_conocidos(self):
        self.assertEqual(puertos.COMUNES[22], "SSH")
        self.assertEqual(puertos.COMUNES[443], "HTTPS")

    def test_rangos_por_modo(self):
        self.assertEqual(len(puertos._rango_puertos("1-1024")), 1024)
        self.assertEqual(len(puertos._rango_puertos("completo")), 65535)
        self.assertEqual(puertos._rango_puertos("comunes"), sorted(puertos.COMUNES))

    def test_puerto_cerrado_no_rompe(self):
        # Un puerto que casi seguro está cerrado en localhost.
        self.assertFalse(puertos._abierto("127.0.0.1", 6553, timeout=0.3))


class Wifi(unittest.TestCase):
    def test_dbm_a_porcentaje(self):
        self.assertEqual(wifi._dbm_a_porcentaje(-30), 100)   # señal fuerte
        self.assertEqual(wifi._dbm_a_porcentaje(-100), 0)    # señal nula
        self.assertTrue(0 <= wifi._dbm_a_porcentaje(-65) <= 100)

    def test_escanear_no_rompe(self):
        # Sea cual sea el sistema, tiene que devolver (lista, aviso) sin lanzar.
        redes, aviso = wifi.escanear()
        self.assertIsInstance(redes, list)
        self.assertIsInstance(aviso, str)


class Consola(unittest.TestCase):
    def test_objetivo_valido_acepta_ip_y_host(self):
        self.assertTrue(consola.objetivo_valido("8.8.8.8"))
        self.assertTrue(consola.objetivo_valido("192.168.1.1"))
        self.assertTrue(consola.objetivo_valido("ejemplo.com"))
        self.assertTrue(consola.objetivo_valido("sub.dominio.com.ar"))

    def test_objetivo_valido_rechaza_inyeccion(self):
        # El corazón de la defensa: ningún metacarácter de shell pasa.
        for malicioso in ["8.8.8.8; rm -rf ~", "a | b", "$(whoami)",
                          "`id`", "1.1.1.1 && reboot", "host con espacios", ""]:
            self.assertFalse(consola.objetivo_valido(malicioso), malicioso)

    def test_catalogo_tiene_lo_esperado(self):
        cat = consola.catalogo()
        self.assertTrue(cat)
        ids = {c["id"] for c in cat}
        self.assertIn("ping", ids)
        self.assertIn("arp", ids)
        self.assertIn("traceroute", ids)
        for c in cat:
            for clave in ("id", "etiqueta", "desc", "objetivo", "programa", "construir", "disponible"):
                self.assertIn(clave, c)
            self.assertIsInstance(c["disponible"], bool)

    def test_buscar(self):
        self.assertIsNotNone(consola.buscar("ping"))
        self.assertIsNone(consola.buscar("no-existe"))

    def test_construir_no_concatena_el_objetivo(self):
        # Aunque el objetivo traiga una inyección, queda como UN solo argumento
        # de la lista: con shell=False nunca se interpreta como comando aparte.
        ping = consola.buscar("ping")
        payload = "8.8.8.8; rm -rf ~"
        argv = ping["construir"](payload)
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[0], ping["programa"])
        self.assertIn(payload, argv)                 # intacto, en un único slot
        self.assertEqual(sum(1 for a in argv if payload in a), 1)

    def test_ejecutar_comando_desconocido(self):
        salida, error = consola.ejecutar("no-existe")
        self.assertEqual(salida, "")
        self.assertTrue(error)

    def test_ejecutar_objetivo_malicioso_no_corre(self):
        # Sea porque el programa no está instalado o porque el objetivo es
        # inválido, nunca ejecuta: devuelve error y salida vacía.
        salida, error = consola.ejecutar("ping", "8.8.8.8; rm -rf ~")
        self.assertEqual(salida, "")
        self.assertTrue(error)


class Dns(unittest.TestCase):
    def test_tipos(self):
        for t in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"):
            self.assertIn(t, dns_.TIPOS)

    def test_disponible_es_bool(self):
        self.assertIsInstance(dns_.disponible(), bool)

    def test_nombre_vacio(self):
        registros, error = dns_.consultar("", "A")
        self.assertEqual(registros, [])
        self.assertTrue(error)

    def test_tipo_no_soportado(self):
        registros, error = dns_.consultar("ejemplo.com", "NOEXISTE")
        self.assertEqual(registros, [])
        self.assertTrue(error)

    def test_formatear(self):
        class _MX:  # noqa: E306
            preference, exchange = 10, "mail.ejemplo.com."
        class _SOA:  # noqa: E306
            mname, rname, serial, refresh = "ns1.ejemplo.com.", "admin.ejemplo.com.", 2024010101, 3600
        class _TXT:  # noqa: E306
            strings = [b"v=spf1 -all"]
        class _Otro:  # noqa: E306
            def to_text(self):
                return "1.2.3.4"
        self.assertIn("mail.ejemplo.com.", dns_._formatear("MX", _MX()))
        self.assertIn("10", dns_._formatear("MX", _MX()))
        self.assertIn("ns1.ejemplo.com.", dns_._formatear("SOA", _SOA()))
        self.assertEqual(dns_._formatear("TXT", _TXT()), "v=spf1 -all")
        self.assertEqual(dns_._formatear("A", _Otro()), "1.2.3.4")


@unittest.skipIf(importlib.util.find_spec("scapy") is None, "scapy no está instalado")
class Sniffer(unittest.TestCase):
    """Clasificación de paquetes con paquetes sintéticos (no captura nada real)."""

    def setUp(self):
        from netscanner.nucleo.sniffer import Sniffer as S
        self.sniffer = S()

    def proto(self, paquete):
        return self.sniffer._resumir(paquete)["proto"]

    def test_ipv4(self):
        from scapy.all import ARP, ICMP, IP, TCP, UDP, Ether
        self.assertEqual(self.proto(Ether() / IP() / TCP()), "TCP")
        self.assertEqual(self.proto(Ether() / IP() / UDP()), "UDP")
        self.assertEqual(self.proto(Ether() / IP() / ICMP()), "ICMP")
        self.assertEqual(self.proto(Ether() / ARP()), "ARP")

    def test_ipv6_tcp_udp(self):
        from scapy.all import TCP, UDP, Ether
        from scapy.layers.inet6 import IPv6
        self.assertEqual(self.proto(Ether() / IPv6() / TCP()), "TCP")
        self.assertEqual(self.proto(Ether() / IPv6() / UDP()), "UDP")

    def test_icmp6(self):
        from scapy.all import Ether
        from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6ND_NS, IPv6
        self.assertEqual(self.proto(Ether() / IPv6() / ICMPv6EchoRequest()), "ICMP6")
        self.assertEqual(self.proto(Ether() / IPv6() / ICMPv6ND_NS()), "ICMP6")

    def test_ipv6_sin_capa4_no_es_icmp6(self):
        from scapy.all import Ether
        from scapy.layers.inet6 import IPv6
        self.assertEqual(self.proto(Ether() / IPv6(nh=59)), "Otro")

    # ---- pausa ----
    def _paquete_udp(self):
        from scapy.all import IP, UDP, Ether
        return Ether() / IP() / UDP(sport=4000, dport=5000)

    def test_pausa_no_registra_y_reanudar_si(self):
        vistos = []
        s = self.sniffer.__class__(al_paquete=vistos.append)
        s._procesar(self._paquete_udp())
        s.pausar()
        self.assertTrue(s.pausado)
        s._procesar(self._paquete_udp())          # en pausa: se descarta
        s._procesar(self._paquete_udp())
        self.assertEqual(s.total, 1)
        s.reanudar()
        self.assertFalse(s.pausado)
        s._procesar(self._paquete_udp())
        self.assertEqual((s.total, len(vistos), s.conteo["UDP"]), (2, 2, 2))

    def test_error_de_placa_inexistente_no_culpa_a_los_permisos(self):
        import scapy.all
        s = self.sniffer.__class__()
        with mock.patch.object(scapy.all, "sniff", side_effect=ValueError("Interface 'x' not found !")):
            s._capturar("x", "")
        self.assertIn("otra placa", s.error)
        self.assertNotIn("sudo", s.error)

    def test_error_de_permisos_sugiere_sudo_o_npcap(self):
        import scapy.all
        for windows, pista in ((False, "sudo"), (True, "Npcap")):
            s = self.sniffer.__class__()
            with mock.patch.object(scapy.all, "sniff", side_effect=PermissionError("Operation not permitted")), \
                    mock.patch("netscanner.nucleo.sniffer.red.ES_WINDOWS", windows):
                s._capturar(None, "")
            self.assertIn(pista, s.error)

    def test_corriendo_es_false_apenas_se_frena(self):
        import threading
        seguir = threading.Event()
        hilo = threading.Thread(target=seguir.wait, daemon=True)   # hilo que «tarda en morir»
        hilo.start()
        s = self.sniffer.__class__()
        s._hilo = hilo
        self.assertTrue(s.corriendo)
        s.frenar()
        self.assertTrue(hilo.is_alive())          # scapy sigue dormido esperando un paquete…
        self.assertFalse(s.corriendo)             # …pero para la interfaz ya no está corriendo
        self.assertTrue(s.detenido)
        seguir.set()

    # ---- DNS visto en la red ----
    def _dns(self, **kw):
        from scapy.all import IP, UDP, Ether
        from scapy.layers.dns import DNS
        return Ether(bytes(Ether() / IP() / UDP(sport=51000, dport=53) / DNS(**kw)))   # como en una captura real

    def test_dns_consulta(self):
        from scapy.layers.dns import DNSQR
        from netscanner.nucleo.sniffer import extraer_dns
        d = extraer_dns(self._dns(rd=1, qd=DNSQR(qname="ejemplo.com", qtype="A")))
        self.assertEqual((d["qr"], d["nombre"], d["tipo"], d["respuestas"]),
                         ("consulta", "ejemplo.com", "A", []))

    def test_dns_respuesta_con_cname_y_ips(self):
        from scapy.layers.dns import DNSQR, DNSRR
        from netscanner.nucleo.sniffer import extraer_dns
        d = extraer_dns(self._dns(
            qr=1, qd=DNSQR(qname="www.ejemplo.com", qtype="A"), ancount=2,
            an=DNSRR(rrname="www.ejemplo.com", type="CNAME", rdata="ejemplo.com") /
               DNSRR(rrname="ejemplo.com", type="A", rdata="93.184.216.34")))
        self.assertEqual(d["qr"], "respuesta")
        self.assertEqual(d["respuestas"], ["ejemplo.com", "93.184.216.34"])

    def test_dns_nxdomain_se_explica(self):
        from scapy.layers.dns import DNSQR
        from netscanner.nucleo.sniffer import extraer_dns
        d = extraer_dns(self._dns(qr=1, rcode=3, qd=DNSQR(qname="no-existe.test", qtype="A")))
        self.assertEqual(d["respuestas"], ["(no existe)"])

    def test_dns_en_resumir_y_paquete_comun_sin_dns(self):
        from scapy.layers.dns import DNSQR
        info = self.sniffer._resumir(self._dns(rd=1, qd=DNSQR(qname="ejemplo.com", qtype="AAAA")))
        self.assertEqual(info["proto"], "UDP")
        self.assertIn("DNS consulta AAAA ejemplo.com", info["detalle"])
        self.assertEqual(info["dns"]["nombre"], "ejemplo.com")
        self.assertIsNone(self.sniffer._resumir(self._paquete_udp())["dns"])


class WifiLinux(unittest.TestCase):
    """Lectura de la salida real de nmcli e iw, sin tocar ninguna placa WiFi."""

    def parche(self, nmcli=(None, -1), iw_dev=(None, -1), iw_scan=(None, -1)):
        def falso(cmd, timeout=15, **kw):
            if cmd[0] == "nmcli":
                return nmcli
            if cmd == ["iw", "dev"]:
                return iw_dev
            if cmd[:2] == ["iw", "dev"] and cmd[-1] == "scan":
                return iw_scan
            return None, -1
        return mock.patch.object(wifi, "_correr", falso)

    def test_partir_nmcli_con_escapes(self):
        self.assertEqual(wifi._partir_nmcli(r"Mi\:Red:74:44:WPA2:AA\:BB\:CC\:DD\:EE\:FF"),
                         ["Mi:Red", "74", "44", "WPA2", "AA:BB:CC:DD:EE:FF"])
        self.assertEqual(wifi._partir_nmcli("barra\\\\:1"), ["barra\\", "1"])   # \\ es una barra; el ':' separa
        self.assertEqual(wifi._partir_nmcli(":50::"), ["", "50", "", ""])

    def test_nmcli_ordena_y_completa_los_vacios(self):
        salida = ("Casa:82:44:WPA2:AA\\:BB\\:CC\\:00\\:11\\:22\n"
                  ":35:6::DD\\:EE\\:FF\\:00\\:11\\:22\n"
                  "Vecino\\:5G:47:100:WPA2 WPA3:12\\:34\\:56\\:78\\:9A\\:BC\n")
        with self.parche(nmcli=(salida, 0)):
            redes, aviso = wifi._linux()
        self.assertEqual(aviso, "")
        self.assertEqual([r["ssid"] for r in redes], ["Casa", "Vecino:5G", "(oculta)"])   # por señal
        self.assertEqual(redes[0]["bssid"], "AA:BB:CC:00:11:22")
        self.assertEqual((redes[2]["seguridad"], redes[2]["canal"]), ("Abierta", "6"))

    def test_si_nmcli_no_anda_prueba_con_iw(self):
        iw_dev = ("phy#0\n\tInterface wlan0\n\t\tifindex 3\n", 0)
        iw_scan = ("BSS aa:bb:cc:00:11:22(on wlan0)\n\tsignal: -45.00 dBm\n\tSSID: CasaIW\n"
                   "\tprimary channel: 44\n\tRSN:\t * Version: 1\n"
                   "BSS dd:ee:ff:00:11:22(on wlan0)\n\tsignal: -80.00 dBm\n\tSSID: \n"
                   "\tDS Parameter set: channel 6\n", 0)
        with self.parche(nmcli=("", 8), iw_dev=iw_dev, iw_scan=iw_scan), \
                mock.patch.object(wifi.red, "es_administrador", return_value=True):
            redes, _ = wifi._linux()
        self.assertEqual([(r["ssid"], r["canal"], r["seguridad"]) for r in redes],
                         [("CasaIW", "44", "WPA2/WPA3"), ("(oculta)", "6", "Abierta")])
        self.assertEqual(redes[0]["bssid"], "AA:BB:CC:00:11:22")

    def test_sin_nmcli_ni_permisos_explica_que_hacer(self):
        with self.parche(), mock.patch.object(wifi.red, "es_administrador", return_value=False):
            redes, aviso = wifi._linux()
        self.assertEqual(redes, [])
        self.assertIn("administrador", aviso)

    def test_en_wsl_lo_explica(self):
        with mock.patch.object(wifi, "_linux", return_value=([], "No se detectaron redes WiFi.")), \
                mock.patch.object(wifi.red, "ES_WINDOWS", False), \
                mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(wifi.red, "en_wsl", return_value=True):
            redes, aviso = wifi.escanear()
        self.assertEqual(redes, [])
        self.assertIn("WSL", aviso)


# Salida típica de 'netsh wlan show networks mode=bssid' en un Windows en español (nombres y BSSID de ejemplo).
NETSH_ES = """
Nombre de interfaz : Wi-Fi
Hay 3 redes visibles en este momento.

SSID 1 : RedFibra-4e1f
    Tipo de red             : Infraestructura
    Autenticación           : WPA2-Personal
    Cifrado                 : CCMP
    BSSID 1                 : 1a:2b:3c:4d:5e:6f
         Señal              : 52%
         Tipo de radio      : 802.11n
         Canal              : 7
         Velocidades básicas (Mbps) : 1 2 5.5 11
         Otras velocidades (Mbps)   : 6 9 12 18 24 36 48 54
    BSSID 2                 : 1a:2b:3c:4d:5e:70
         Señal              : 81%
         Tipo de radio      : 802.11ac
         Canal              : 44
         Velocidades básicas (Mbps) : 6 12 24
         Otras velocidades (Mbps)   : 9 18 36 48 54

SSID 2 : Cafe Libre
    Tipo de red             : Infraestructura
    Autenticación           : Abierta
    Cifrado                 : Ninguna
    BSSID 1                 : aa:bb:cc:00:11:22
         Señal              : 63%
         Tipo de radio      : 802.11g
         Canal              : 11

SSID 3 :
    Tipo de red             : Infraestructura
    Autenticación           : WPA2-Enterprise
    Cifrado                 : CCMP
    BSSID 1                 : de:ad:be:ef:00:01
         Señal              : 30%
         Tipo de radio      : 802.11n
         Canal              : 1
"""

# Lo mismo en un Windows 11 en inglés, con las líneas nuevas (Band, Bss Load).
NETSH_EN = """
Interface name : Wi-Fi
There are 1 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 90%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 100
         Bss Load:
             Connected Stations:        4
             Channel Utilization:       35 (13 %)
             Medium Available Capacity: 38000 (µs/s)
         Basic rates (Mbps) : 6 12 24
         Other rates (Mbps) : 9 18 36 48 54
"""


class WifiWindows(unittest.TestCase):
    """Error corregido: todas las redes salían «Abierta» con 0 % de señal."""

    def test_espanol_lee_seguridad_senal_y_canal(self):
        redes = wifi._parsear_netsh(NETSH_ES)
        self.assertEqual([(r["ssid"], r["senal"], r["canal"], r["seguridad"]) for r in redes],
                         [("RedFibra-4e1f", 81, "44", "WPA2-Personal"),    # el punto de acceso más fuerte
                          ("Cafe Libre", 63, "11", "Abierta"),
                          ("(oculta)", 30, "1", "WPA2-Enterprise")])
        self.assertEqual(redes[0]["bssid"], "1A:2B:3C:4D:5E:70")

    def test_ingles_con_las_lineas_de_windows_11(self):
        redes = wifi._parsear_netsh(NETSH_EN)
        self.assertEqual([(r["ssid"], r["senal"], r["canal"], r["seguridad"]) for r in redes],
                         [("HomeNet", 90, "100", "WPA3-Personal")])

    def test_no_depende_de_la_codificacion_ni_del_idioma(self):
        # Aunque los acentos lleguen rotos («Autenticaci¢n»), se lee igual por estructura.
        roto = NETSH_ES.encode("cp850").decode("cp1252")
        self.assertIn("Autenticaci¢n", roto)
        self.assertEqual(wifi._parsear_netsh(roto), wifi._parsear_netsh(NETSH_ES))

    def test_ninguna_red_cae_en_abierta_por_defecto(self):
        # Antes, lo que no se entendía quedaba como «Abierta». Ahora queda como «?».
        sin_seguridad = "SSID 1 : Rara\n    BSSID 1 : 00:00:00:00:00:01\n         Signal : 10%\n"
        self.assertEqual(wifi._parsear_netsh(sin_seguridad)[0]["seguridad"], "?")

    def test_windows_lee_la_salida_con_la_codificacion_de_la_consola(self):
        # netsh escribe en cp850 en un Windows en español. Se prueba el camino completo.
        falso = subprocess.CompletedProcess([], 0, stdout=NETSH_ES.encode("cp850"), stderr=b"")
        with mock.patch.object(wifi.subprocess, "run", return_value=falso), \
                mock.patch.object(wifi.red, "codificacion_consola", return_value="cp850"):
            redes, aviso = wifi._windows()
        self.assertEqual(aviso, "")
        self.assertEqual(redes[0]["seguridad"], "WPA2-Personal")
        self.assertEqual(redes[0]["senal"], 81)

    def test_sin_redes_explica_las_causas(self):
        falso = subprocess.CompletedProcess([], 1, stdout=b"El servicio WLAN no se esta ejecutando.", stderr=b"")
        with mock.patch.object(wifi.subprocess, "run", return_value=falso):
            redes, aviso = wifi._windows()
        self.assertEqual(redes, [])
        self.assertIn("ubicación", aviso)

    def test_la_consola_de_windows_no_rompe_los_acentos(self):
        falso = subprocess.CompletedProcess([], 0, stdout="Dirección física".encode("cp850"), stderr=b"")
        with mock.patch.object(consola.subprocess, "run", return_value=falso), \
                mock.patch.object(consola.shutil, "which", return_value="/bin/x"), \
                mock.patch.object(consola.red, "codificacion_consola", return_value="cp850"):
            salida, error = consola.ejecutar("interfaces")
        self.assertEqual((salida, error), ("Dirección física", ""))


class WifiConectar(unittest.TestCase):
    """Conectarse a una red: qué se le pide al sistema, y que la clave no se filtre."""

    def _windows(self, respuestas):
        """Parchea _correr como si fuera Windows. Anota cada llamada y, en la de
        'add profile', revisa que el archivo temporal exista y lleve la clave."""
        llamadas, visto = [], {}

        def falso(cmd, timeout=15, **kw):
            llamadas.append(list(cmd))
            if cmd[:4] == ["netsh", "wlan", "add", "profile"]:
                ruta = cmd[4].split("=", 1)[1]
                visto["ruta"] = ruta
                visto["existia"] = os.path.isfile(ruta)
                visto["contenido"] = ""
                if visto["existia"]:
                    with open(ruta, encoding="utf-8") as f:
                        visto["contenido"] = f.read()
            for prefijo, resp in respuestas:
                if cmd[:len(prefijo)] == prefijo:
                    return resp(len(llamadas)) if callable(resp) else resp
            return "", 0
        return llamadas, visto, falso

    def test_validaciones_sin_tocar_el_sistema(self):
        with mock.patch.object(wifi, "_correr") as correr:
            self.assertFalse(wifi.conectar("", "x", "WPA2-Personal")[0])
            self.assertFalse(wifi.conectar("(oculta)", "x", "WPA2-Personal")[0])
            ok, msg = wifi.conectar("MiRed", "", "WPA2-Personal")
            self.assertFalse(ok)
            self.assertIn("tiene clave", msg)
            self.assertFalse(wifi.conectar("Mi\nRed", "x", "Abierta")[0])
            correr.assert_not_called()

    def test_tipo_de_seguridad_a_perfil_de_windows(self):
        casos = {"WPA2-Personal": ("WPA2PSK", "AES"), "WPA3-Personal": ("WPA3SAE", "AES"),
                 "WPA-Personal": ("WPAPSK", "TKIP"), "Abierta": ("open", "none"), "Open": ("open", "none"),
                 "WPA2-Enterprise": None, "WEP": None, "?": None}
        for seguridad, esperado in casos.items():
            self.assertEqual(wifi._auth_windows(seguridad), esperado, seguridad)

    def test_perfil_xml_es_valido_y_escapa_la_clave(self):
        clave = 'p&ss<w>rd"1\''
        raiz = ET.fromstring(wifi._perfil_xml("Mi & Red", clave, "WPA2PSK", "AES"))
        ns = {"p": "http://www.microsoft.com/networking/WLAN/profile/v1"}
        self.assertEqual(raiz.find("p:name", ns).text, "Mi & Red")
        self.assertEqual(raiz.find(".//p:keyMaterial", ns).text, clave)
        self.assertEqual(raiz.find(".//p:authentication", ns).text, "WPA2PSK")
        abierta = ET.fromstring(wifi._perfil_xml("Cafe", "", "open", "none"))
        self.assertIsNone(abierta.find(".//p:sharedKey", ns))

    def test_windows_conecta_y_no_deja_la_clave_en_ningun_lado(self):
        clave = "secreta123"
        conectada = "    Nombre       : Wi-Fi\n    SSID                   : MiRed\n    BSSID : aa:bb:cc:dd:ee:ff\n"
        respuestas = [(["netsh", "wlan", "show", "interfaces"],
                       lambda n: (conectada if n > 4 else "    Estado : desconectado\n", 0))]
        llamadas, visto, falso = self._windows(respuestas)
        with mock.patch.object(wifi.red, "ES_WINDOWS", True), mock.patch.object(wifi, "_correr", falso), \
                mock.patch.object(wifi.time, "sleep"):
            ok, msg = wifi.conectar("MiRed", clave, "WPA2-Personal")
        self.assertTrue(ok, msg)
        self.assertIn("Conectado a MiRed", msg)
        self.assertTrue(visto["existia"])
        self.assertIn(clave, visto["contenido"])                       # el perfil la lleva…
        self.assertFalse(os.path.exists(visto["ruta"]))                # …y se borra apenas se importa
        self.assertFalse(any(clave in arg for cmd in llamadas for arg in cmd))   # nunca va en la línea de comandos
        self.assertEqual([c[2] for c in llamadas[:2]], ["add", "connect"])

    def test_windows_clave_incorrecta_lo_dice(self):
        llamadas, visto, falso = self._windows([])                    # nunca aparece conectada
        with mock.patch.object(wifi.red, "ES_WINDOWS", True), mock.patch.object(wifi, "_correr", falso), \
                mock.patch.object(wifi.time, "sleep"):
            ok, msg = wifi.conectar("MiRed", "claveMala1", "WPA2-Personal")
        self.assertFalse(ok)
        self.assertIn("Revisá la clave", msg)
        self.assertFalse(os.path.exists(visto["ruta"]))

    def test_windows_perfil_rechazado_borra_el_temporal(self):
        llamadas, visto, falso = self._windows([(["netsh", "wlan", "add"], ("Error de perfil\n", 1))])
        with mock.patch.object(wifi.red, "ES_WINDOWS", True), mock.patch.object(wifi, "_correr", falso):
            ok, msg = wifi.conectar("MiRed", "claveOk123", "WPA2-Personal")
        self.assertFalse(ok)
        self.assertIn("no aceptó", msg)
        self.assertFalse(os.path.exists(visto["ruta"]))
        self.assertEqual(len(llamadas), 1)                             # ni siquiera intentó conectar

    def test_windows_clave_corta_y_redes_de_empresa(self):
        with mock.patch.object(wifi.red, "ES_WINDOWS", True), mock.patch.object(wifi, "_correr") as correr:
            self.assertIn("8 y 63", wifi.conectar("MiRed", "corta", "WPA2-Personal")[1])
            self.assertIn("empresa", wifi.conectar("MiRed", "claveOk123", "WPA2-Enterprise")[1])
            correr.assert_not_called()

    def _linux(self, resultado):
        llamadas = []

        def falso(cmd, timeout=15, **kw):
            llamadas.append(list(cmd))
            return resultado
        return llamadas, falso

    def test_linux_arma_el_comando_sin_shell(self):
        llamadas, falso = self._linux(("Device 'wlan0' successfully activated.\n", 0))
        raro = "Red; rm -rf ~ $(id)"
        with mock.patch.object(wifi.red, "ES_WINDOWS", False), mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(wifi, "_correr", falso):
            ok, msg = wifi.conectar(raro, "secreta123", "WPA2")
        self.assertTrue(ok, msg)
        self.assertEqual(llamadas[0], ["nmcli", "--wait", "30", "device", "wifi", "connect", raro,
                                       "password", "secreta123"])      # el nombre raro es UN solo argumento

    def test_linux_red_abierta_ignora_la_clave(self):
        llamadas, falso = self._linux(("", 0))
        with mock.patch.object(wifi.red, "ES_WINDOWS", False), mock.patch.object(sys, "platform", "linux"), \
                mock.patch.object(wifi, "_correr", falso):
            ok, _ = wifi.conectar("Cafe", "lo que sea", "Abierta")
        self.assertTrue(ok)
        self.assertNotIn("password", llamadas[0])

    def test_linux_explica_clave_mala_y_falta_de_nmcli(self):
        with mock.patch.object(wifi.red, "ES_WINDOWS", False), mock.patch.object(sys, "platform", "linux"):
            _, falso = self._linux(("Error: Connection activation failed: (7) Secrets were required, but not provided.", 4))
            with mock.patch.object(wifi, "_correr", falso):
                self.assertIn("clave parece incorrecta", wifi.conectar("MiRed", "mala12345", "WPA2")[1])
            _, falso = self._linux((None, -1))
            with mock.patch.object(wifi, "_correr", falso):
                self.assertIn("NetworkManager", wifi.conectar("MiRed", "clave12345", "WPA2")[1])


def _placa(nombre, ipv4="", activa=True):
    return {"nombre": nombre, "ipv4": ipv4, "ipv6": "", "mac": "AA-BB", "activa": activa,
            "velocidad": 0, "es_loopback": False}


class Interfaz(unittest.TestCase):
    """La pantalla, sin terminal real (Textual la maneja en memoria)."""

    def _correr(self, prueba, placas=None):
        """Abre la aplicación, le da 'prueba(app, pilot)' y la cierra. 'placas' reemplaza
        la lista de interfaces de la máquina."""
        from netscanner.app import NetScanner

        async def principal():
            app = NetScanner()
            async with app.run_test(size=(110, 30)) as pilot:
                await pilot.pause(0.3)
                await prueba(app, pilot)

        with tempfile.TemporaryDirectory() as tmp:
            estado = os.getcwd()
            os.chdir(tmp)                     # que «resultados/» no ensucie el proyecto
            try:
                with mock.patch.object(exportar, "CARPETA", os.path.join(tmp, "resultados")):
                    if placas is None:
                        asyncio.run(principal())
                    else:
                        with mock.patch.object(red, "interfaces", return_value=placas), \
                                mock.patch.object(red, "interfaz_activa", return_value=placas[0]):
                            asyncio.run(principal())
            finally:
                os.chdir(estado)

    def test_el_selector_de_placa_se_llena_y_la_elegida_llega_al_sniffer(self):
        from textual.widgets import Select, TabbedContent
        from netscanner.nucleo import sniffer
        placas = [_placa("Ethernet", "10.0.0.7"), _placa("Wi-Fi", "192.168.1.5"),
                  _placa("Bluetooth", "", activa=False)]

        async def prueba(app, pilot):
            selector = app.query_one("#sel-iface", Select)
            etiquetas = [str(o[0]) for o in selector._options]
            self.assertIn("Wi-Fi (192.168.1.5)", etiquetas)
            self.assertNotIn("Bluetooth", " ".join(etiquetas))         # sin IP y apagada: no sirve
            self.assertEqual(selector.value, "")                       # por defecto: automática
            selector.value = "Wi-Fi"
            app.query_one(TabbedContent).active = "tab-paq"
            await pilot.pause(0.3)
            await pilot.click("#btn-sniff")
            await pilot.pause(0.2)

        with mock.patch.object(sniffer.Sniffer, "disponible", return_value=(True, "")), \
                mock.patch.object(sniffer.Sniffer, "arrancar", autospec=True, return_value=True) as arrancar:
            self._correr(prueba, placas)
        self.assertEqual(arrancar.call_args.kwargs["interfaz"], "Wi-Fi")

    def test_sin_elegir_placa_captura_en_la_automatica(self):
        from textual.widgets import TabbedContent
        from netscanner.nucleo import sniffer

        async def prueba(app, pilot):
            app.query_one(TabbedContent).active = "tab-paq"
            await pilot.pause(0.3)
            await pilot.click("#btn-sniff")
            await pilot.pause(0.2)

        with mock.patch.object(sniffer.Sniffer, "disponible", return_value=(True, "")), \
                mock.patch.object(sniffer.Sniffer, "arrancar", autospec=True, return_value=True) as arrancar:
            self._correr(prueba, [_placa("Ethernet", "10.0.0.5")])
        self.assertIsNone(arrancar.call_args.kwargs["interfaz"])

    def test_una_captura_que_se_corta_lo_avisa(self):
        from textual.widgets import Button, Label
        from netscanner.nucleo.sniffer import Sniffer as S

        async def prueba(app, pilot):
            s = S()
            s._hilo = threading.Thread(target=lambda: None)            # un hilo que ya terminó…
            s._hilo.start()
            s._hilo.join()
            s.error = "Interface 'no-existe' not found. ¿Está instalado Npcap?"   # …por un error
            app._sniff = s
            app._sniff_ui(True)
            app._vigilar_captura()
            texto = str(getattr(app.query_one("#est-paq", Label), "content", ""))
            self.assertIn("La captura se cortó", texto)
            self.assertIn("Npcap", texto)
            self.assertEqual(str(app.query_one("#btn-sniff", Button).label), "Capturar")
            self.assertTrue(s.detenido)

        self._correr(prueba)

    def test_una_placa_sin_ip_no_salta_a_descubrimiento(self):
        from textual.widgets import DataTable, TabbedContent

        async def prueba(app, pilot):
            tabs = app.query_one(TabbedContent)
            tabs.active = "tab-puertos"
            await pilot.pause(0.3)
            tabla = app.query_one("#tabla-if", DataTable)
            fila = [str(tabla.get_row_at(i)[0]) for i in range(tabla.row_count)].index("Wi-Fi")
            self.assertEqual(str(tabla.get_row_at(fila)[4]), "sin IP")
            tabla.focus()
            tabla.move_cursor(row=fila)
            await pilot.press("enter")
            await pilot.pause(0.3)
            self.assertEqual(tabs.active, "tab-puertos")               # no cambió de pestaña

        self._correr(prueba, [_placa("Ethernet", "10.0.0.5"), _placa("Wi-Fi", "169.254.10.20")])

    def test_conectar_usa_la_red_elegida_y_borra_la_clave(self):
        from textual.widgets import Button, DataTable, Input, Label
        llamadas = []

        async def prueba(app, pilot):
            await pilot.click("#btn-conectar")                          # todavía no escaneó nada
            await pilot.pause(0.2)
            self.assertIn("Escanear WiFi", str(getattr(app.query_one("#est-wifi", Label), "content", "")))
            app._redes_wifi = [{"ssid": "RedUno", "senal": 81, "canal": "44", "seguridad": "WPA2-Personal", "bssid": ""},
                               {"ssid": "RedDos", "senal": 63, "canal": "6", "seguridad": "WPA2-Personal", "bssid": ""}]
            tabla = app.query_one("#tabla-wifi", DataTable)
            for r in app._redes_wifi:
                tabla.add_row(r["ssid"], "", str(r["senal"]), r["canal"], "WPA2")
            tabla.move_cursor(row=1)
            app.query_one("#in-clave", Input).value = "miClave123"
            await pilot.click("#btn-conectar")
            await pilot.pause(0.6)
            self.assertEqual(llamadas, [("RedDos", "miClave123", "WPA2-Personal")])
            self.assertEqual(app.query_one("#in-clave", Input).value, "")   # la clave no queda a la vista
            self.assertEqual(str(app.query_one("#btn-conectar", Button).label), "Conectar")
            self.assertIn("Conectado a RedDos", str(getattr(app.query_one("#est-wifi", Label), "content", "")))

        def falso(ssid, clave, seguridad):
            llamadas.append((ssid, clave, seguridad))
            return True, "Conectado a %s." % ssid

        with mock.patch.object(wifi, "conectar", falso):
            self._correr(prueba)


class Wsl(unittest.TestCase):
    def _con_version(self, texto):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        ruta = os.path.join(d, "version")
        with open(ruta, "w", encoding="utf-8") as f:
            f.write(texto)
        return mock.patch.object(red, "_PROC_VERSION", ruta)

    def test_detecta_wsl2_y_wsl1(self):
        with mock.patch.object(red, "ES_WINDOWS", False):
            with self._con_version("Linux version 5.15.153.1-microsoft-standard-WSL2 (root@host)"):
                self.assertTrue(red.en_wsl())
            with self._con_version("Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com)"):
                self.assertTrue(red.en_wsl())

    def test_linux_comun_no_es_wsl(self):
        with mock.patch.object(red, "ES_WINDOWS", False), \
                self._con_version("Linux version 6.8.0-45-generic (buildd@lcy02) (gcc 13.2.0)"):
            self.assertFalse(red.en_wsl())

    def test_sin_proc_version_o_en_windows(self):
        with mock.patch.object(red, "ES_WINDOWS", False), mock.patch.object(red, "_PROC_VERSION", "/no/existe"):
            self.assertFalse(red.en_wsl())
        with mock.patch.object(red, "ES_WINDOWS", True):
            self.assertFalse(red.en_wsl())

    def test_como_elevar_en_linux_apunta_al_lanzador(self):
        with mock.patch.object(red, "ES_WINDOWS", False):
            self.assertIn("sudo ./iniciar.sh", red.como_elevar())
            self.assertEqual(red.como_elevar_corto(), "sudo ./iniciar.sh")

    def test_como_elevar_corto_en_windows(self):
        with mock.patch.object(red, "ES_WINDOWS", True):
            self.assertIn("administrador", red.como_elevar_corto())


class Recientes(unittest.TestCase):
    def test_reasignar_deja_la_clave_al_final(self):
        from netscanner.app import _Recientes
        d = _Recientes()
        d["descubrimiento"] = 1
        d["puertos"] = 2
        d["descubrimiento"] = 3          # se volvió a correr el descubrimiento
        self.assertEqual(list(d)[-1], "descubrimiento")
        self.assertEqual(d["descubrimiento"], 3)


class Exportar(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig = exportar.CARPETA
        exportar.CARPETA = self.tmp

    def tearDown(self):
        exportar.CARPETA = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_csv_con_diccionarios(self):
        datos = [{"ip": "1.1.1.1", "puerto": 80}, {"ip": "1.1.1.1", "puerto": 443}]
        ruta = exportar.guardar_csv("puertos", "1.1.1.1", datos)
        self.assertTrue(os.path.isfile(ruta))
        with open(ruta, encoding="utf-8") as f:
            txt = f.read()
        self.assertIn("ip,puerto", txt)   # encabezado
        self.assertIn("443", txt)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "solo tiene sentido como root")
    def test_con_sudo_lo_creado_queda_a_nombre_del_usuario(self):
        with mock.patch.dict(os.environ, {"SUDO_UID": "54321", "SUDO_GID": "54322"}):
            ruta = exportar.guardar_csv("puertos", "1.1.1.1", [{"puerto": 80}])
        for camino in (ruta, exportar.CARPETA):
            st = os.stat(camino)
            self.assertEqual((st.st_uid, st.st_gid), (54321, 54322), camino)

    def test_sin_sudo_no_toca_los_duenos(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SUDO_UID", None)
            with mock.patch.object(exportar.os, "chown") as chown:
                exportar.guardar_csv("dns", "x", ["1.2.3.4"])
            chown.assert_not_called()

    def test_csv_con_textos(self):
        ruta = exportar.guardar_csv("dns", "google.com", ["1.2.3.4", "5.6.7.8"])
        with open(ruta, encoding="utf-8") as f:
            txt = f.read()
        self.assertIn("1.2.3.4", txt)
        self.assertIn("5.6.7.8", txt)


if __name__ == "__main__":
    unittest.main()
