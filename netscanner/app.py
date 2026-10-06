"""Interfaz de NetScanner: un panel (dashboard) en la terminal, al estilo del
netscanner de Chleba (el original en Rust).

Arriba, siempre a la vista: las redes WiFi y las interfaces de la máquina (con
su IPv4, IPv6 y MAC). Abajo, en pestañas: descubrimiento, puertos, captura de
paquetes (con filtro por protocolo: ARP/TCP/UDP/ICMP/ICMP6), conteo de tráfico,
DNS y comandos de consola. Los escaneos corren en hilos aparte (@work) para que
la interfaz nunca se congele, y todo se puede cancelar con Esc.
"""

from __future__ import annotations

import ipaddress
import os
import threading
from collections import Counter, deque

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import (Button, DataTable, Footer, Header, Input, Label,
                             RichLog, Select, Static, TabbedContent, TabPane)

from . import __version__
from .nucleo import (consola, descubrimiento, dns_, exportar, nmap_, puertos,
                     red, sniffer, wifi)

PROTOS = ["TODOS", "ARP", "TCP", "UDP", "ICMP", "ICMP6"]


class _Recientes(dict):
    """dict que deja al final la clave asignada más recientemente, para que
    «exportar el último resultado» exporte de verdad el último."""

    def __setitem__(self, clave, valor):
        self.pop(clave, None)
        super().__setitem__(clave, valor)


def _barra(porcentaje, ancho=8):
    """Barrita de texto para la señal WiFi: ▓▓▓▓▓░░░"""
    llenos = round(porcentaje / 100 * ancho)
    return "▓" * llenos + "░" * (ancho - llenos)


class NetScanner(App):
    TITLE = "NetScanner"
    CSS = """
    Screen { background: $surface; }
    #sub { color: $text-muted; height: 1; content-align: center middle; }

    #paneles { height: auto; }
    .panel { border: round $primary; height: auto; }
    #panel-wifi { width: 1fr; margin-right: 1; }
    #col-if { width: 1fr; height: auto; }
    #panel-activa { height: 3; padding: 0 1; }
    #tabla-wifi { height: 5; }
    #tabla-if { height: 4; }
    #panel-wifi Button { margin: 0; width: auto; min-width: 10; height: 1; border: none; }
    #fila-wifi { height: 1; }
    #in-clave { width: 1fr; height: 1; border: none; padding: 0 1; margin: 0 1; }
    #est-wifi, #info-activa { padding: 0 1; }

    #tabs { height: 1fr; }
    TabPane { padding: 0; }
    TabPane DataTable { height: 1fr; }
    #traf-cols { height: 1fr; }
    #traf-cols DataTable { width: 1fr; height: 1fr; }
    #traf-cols #tabla-dnsv { width: 2fr; }

    .barra-controles { height: auto; padding: 0 1; }
    .barra-controles Input { width: 1fr; }
    .barra-controles Select { width: 22; }
    .barra-controles Button { margin-left: 1; }
    #filtro-proto { height: 1; padding: 0 1; }
    #filtro-proto Button { margin: 0 1 0 0; min-width: 8; height: 1; border: none; }

    .estado { width: 1fr; height: auto; padding: 0 1; color: $text-muted; }
    .aviso { color: $warning; }
    .ok { color: $success; }
    #barra-abajo { height: auto; min-height: 1; padding: 0 1; }
    #barra-abajo Button { margin: 0 1 0 0; height: 1; border: none; min-width: 8; }
    #rotulo-exp { width: auto; padding: 0 1 0 0; }
    RichLog { height: 1fr; background: $surface; }
    """
    BINDINGS = [
        ("q", "quit", "Salir"),
        ("d", "toggle_dark", "Tema"),
        ("p", "pausar", "Pausar/Reanudar captura"),
        ("escape", "cancelar", "Cancelar escaneo"),
    ]

    def __init__(self):
        super().__init__()
        self._cancel = {}                 # nombre -> threading.Event
        self._sniff = None                # instancia de Sniffer
        self._ultimo = _Recientes()       # tipo -> (objetivo, datos) para exportar
        self._paquetes = deque(maxlen=500)  # buffer para filtrar por protocolo
        self._filtro = "TODOS"            # filtro de protocolo activo
        self._origenes = Counter()        # conteo de tráfico por IP de origen
        self._redes_wifi = []             # redes del último escaneo, en el orden de la tabla
        self._dns_vistos = {}             # (nombre, tipo) -> {"resp": [...], "veces": n}
        self._traf_sucio = False          # hay datos nuevos para mostrar en Tráfico

    # ------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(f"NetScanner · escáner de red · v{__version__} · usá SOLO en redes propias o autorizadas",
                     id="sub")

        # ---- panel superior fijo: WiFi (izq) | Interfaces + activa (der) ----
        with Horizontal(id="paneles"):
            with Container(id="panel-wifi", classes="panel"):
                yield DataTable(id="tabla-wifi", cursor_type="row")
                with Horizontal(id="fila-wifi"):
                    yield Button("Escanear WiFi", id="btn-wifi", variant="primary")
                    yield Input(placeholder="Clave (vacía si es abierta)", password=True, id="in-clave")
                    yield Button("Conectar", id="btn-conectar")
                yield Label("", id="est-wifi", classes="estado")
            with Vertical(id="col-if"):
                with Container(id="panel-if", classes="panel"):
                    yield DataTable(id="tabla-if", cursor_type="row")
                with Container(id="panel-activa", classes="panel"):
                    yield Static("", id="info-activa")

        # ---- pestañas de trabajo ----
        with TabbedContent(id="tabs", initial="tab-desc"):
            with TabPane("Descubrimiento", id="tab-desc"):
                with Horizontal(classes="barra-controles"):
                    yield Input(placeholder="Rango, ej. 192.168.1.0/24", id="in-rango")
                    yield Button("Escanear", id="btn-desc", variant="primary")
                yield Label("", id="est-desc", classes="estado")
                yield DataTable(id="tabla-desc", cursor_type="row")

            with TabPane("Puertos", id="tab-puertos"):
                with Horizontal(classes="barra-controles"):
                    yield Input(placeholder="IP objetivo, ej. 192.168.1.1", id="in-obj")
                    yield Select([("Comunes (~45)", "comunes"), ("1-1024", "1-1024"),
                                  ("1-10000", "1-10000"), ("Completo 1-65535", "completo")],
                                 value="comunes", id="sel-modo", allow_blank=False)
                    yield Button("Escanear", id="btn-puertos", variant="primary")
                    yield Button("nmap", id="btn-nmap")
                yield Label("", id="est-puertos", classes="estado")
                yield DataTable(id="tabla-puertos", cursor_type="row")

            with TabPane("Paquetes", id="tab-paq"):
                with Horizontal(classes="barra-controles"):
                    yield Input(placeholder="Filtro BPF opcional, ej. tcp port 80", id="in-filtro")
                    yield Select([("Placa: automática", "")], value="", id="sel-iface", allow_blank=False)
                    yield Button("Capturar", id="btn-sniff", variant="primary")
                    yield Button("Pausar", id="btn-pausa", disabled=True)
                with Horizontal(id="filtro-proto"):
                    for p in PROTOS:
                        yield Button(p.capitalize() if p == "TODOS" else p, id=f"f-{p.lower()}",
                                     variant="primary" if p == "TODOS" else "default")
                yield Label("", id="est-paq", classes="estado")
                yield DataTable(id="tabla-paq", cursor_type="row")

            with TabPane("Tráfico", id="tab-traf"):
                yield Label("En vivo mientras capturás en «Paquetes». Los DNS se ven solo si van "
                            "sin cifrar (puerto 53 y mDNS).", id="est-traf", classes="estado")
                with Horizontal(id="traf-cols"):
                    yield DataTable(id="tabla-traf", cursor_type="row")
                    yield DataTable(id="tabla-top", cursor_type="row")
                    yield DataTable(id="tabla-dnsv", cursor_type="row")

            with TabPane("DNS", id="tab-dns"):
                with Horizontal(classes="barra-controles"):
                    yield Input(placeholder="Dominio o IP, ej. google.com", id="in-dns")
                    yield Select([(t, t) for t in dns_.TIPOS], value="A", id="sel-tipo", allow_blank=False)
                    yield Select(dns_.SERVIDORES, value="", id="sel-dns", allow_blank=False)
                    yield Button("Consultar", id="btn-dns", variant="primary")
                yield Label("Registros DNS (A, AAAA, MX, NS, TXT…) e inverso (PTR).",
                            id="est-dns", classes="estado")
                yield DataTable(id="tabla-dns", cursor_type="row")

            with TabPane("Consola", id="tab-consola"):
                opciones = [(c["etiqueta"], c["id"]) for c in consola.catalogo()]
                with Horizontal(classes="barra-controles"):
                    yield Select(opciones, value=opciones[0][1], id="sel-cmd", allow_blank=False)
                    yield Input(placeholder="Objetivo (solo ping/traceroute/nslookup/dig)", id="in-cmd-obj")
                    yield Button("Ejecutar", id="btn-cmd", variant="primary")
                yield Label("Comandos de red seguros: menú fijo, sin shell abierta.",
                            id="est-cmd", classes="estado")
                yield RichLog(id="log-cmd", highlight=False, markup=False, wrap=True)

        # ---- barra inferior: exportar ----
        with Horizontal(id="barra-abajo"):
            yield Label("Exportar:", id="rotulo-exp")
            yield Button("JSON", id="btn-json")
            yield Button("CSV", id="btn-csv")
            yield Button("TXT", id="btn-txt")
            yield Label("Se guarda en la carpeta 'resultados'.", id="est-exp", classes="estado")
        yield Footer()

    # ------------------------------------------------------------------
    def on_mount(self):
        self.query_one("#panel-wifi").border_title = "Redes WiFi"
        self.query_one("#panel-if").border_title = "Interfaces"
        self.query_one("#panel-activa").border_title = "Interfaz activa"
        self.query_one("#tabla-wifi", DataTable).add_columns("SSID", "Señal", "%", "Canal", "Seg")
        self.query_one("#tabla-if", DataTable).add_columns("Interfaz", "IPv4", "IPv6", "MAC", "Estado")
        self.query_one("#tabla-desc", DataTable).add_columns("IP", "Nombre", "MAC", "Fabricante", "Método")
        self.query_one("#tabla-puertos", DataTable).add_columns("Puerto", "Servicio", "Banner")
        self.query_one("#tabla-paq", DataTable).add_columns("Hora", "Proto", "Origen", "Destino", "Long", "Detalle")
        self.query_one("#tabla-traf", DataTable).add_columns("Protocolo", "Paquetes", "%")
        self.query_one("#tabla-top", DataTable).add_columns("Origen", "Paquetes")
        self.query_one("#tabla-dnsv", DataTable).add_columns("Nombre", "Tipo", "Respuesta", "Veces")
        self.query_one("#tabla-dns", DataTable).add_columns("Tipo", "Resultado")
        self.query_one("#in-rango", Input).value = red.rango_local()
        act = red.interfaz_activa()
        if act:
            self.query_one("#in-obj", Input).value = act["ipv4"]
        self._cargar_interfaces()
        self._actualizar_ayuda_consola()
        self.set_interval(1.0, self._refrescar_trafico)
        avisos = []
        if not red.es_administrador():
            avisos.append("Sin permisos: solo ping. Para MAC y captura: " + red.como_elevar_corto() + ".")
        if red.en_wsl():
            avisos.append("Estás en WSL: ves su red virtual, no tu red real (más en el README).")
        if avisos:
            self._estado("est-desc", " ".join(avisos), "aviso")

    def on_resize(self, evento):
        """En terminales bajas sacamos el subtítulo, para que entren más filas de resultados."""
        try:
            self.query_one("#sub").display = self.size.height >= 28
        except NoMatches:
            pass

    # ---- helpers de UI ----
    def _estado(self, id_, texto, clase=""):
        w = self.query_one(f"#{id_}", Label)
        w.update(texto)
        w.set_classes(f"estado {clase}".strip())

    def _boton(self, id_, etiqueta, variante):
        b = self.query_one(f"#{id_}", Button)
        b.label = etiqueta
        b.variant = variante

    def _cancel_para(self, nombre):
        ev = threading.Event()
        self._cancel[nombre] = ev
        return ev

    def action_cancelar(self):
        for ev in self._cancel.values():
            ev.set()
        if self._sniff and self._sniff.corriendo:
            self._detener_captura()
        self.notify("Escaneos cancelados.", timeout=2)

    # ------------------------------------------------------------------
    def on_button_pressed(self, evento: Button.Pressed):
        bid = evento.button.id or ""
        if bid.startswith("f-"):                 # botones de filtro de protocolo
            self._set_filtro(bid[2:].upper())
            return
        acciones = {
            "btn-wifi": self._accion_wifi,
            "btn-conectar": self._accion_conectar,
            "btn-desc": self._accion_descubrir,
            "btn-puertos": self._accion_puertos,
            "btn-nmap": self._accion_nmap,
            "btn-sniff": self._accion_sniff,
            "btn-pausa": self._accion_pausa,
            "btn-dns": self._accion_dns,
            "btn-cmd": self._accion_consola,
            "btn-json": lambda: self._exportar("json"),
            "btn-csv": lambda: self._exportar("csv"),
            "btn-txt": lambda: self._exportar("txt"),
        }
        accion = acciones.get(bid)
        if accion:
            accion()

    # ---- INTERFACES (panel fijo) ----
    def _cargar_interfaces(self):
        tabla = self.query_one("#tabla-if", DataTable)
        tabla.clear()
        activa = red.interfaz_activa()
        lista = red.interfaces()
        for i in lista:
            marca = " ◀" if activa and i["nombre"] == activa["nombre"] else ""
            if i["ipv4"].startswith("169.254."):
                estado = "sin IP"             # 169.254.x.x: la placa no consiguió una dirección de ninguna red
            else:
                estado = "up" if i["activa"] else "down"
            tabla.add_row(i["nombre"] + marca, i["ipv4"] or "—", i["ipv6"] or "—",
                          i["mac"] or "—", estado)
        self._info_activa()
        self._actualizar_selector_placas(lista)

    def _actualizar_selector_placas(self, lista):
        """Deja elegir en qué placa capturar. Sin esto, la captura siempre usaría la placa
        por defecto (la de la LAN) aunque estés conectado por WiFi."""
        try:
            selector = self.query_one("#sel-iface", Select)
        except NoMatches:
            return
        opciones = [("Placa: automática", "")]
        for i in lista:
            if i["ipv4"] or i["activa"]:
                opciones.append((i["nombre"] + (f" ({i['ipv4']})" if i["ipv4"] else ""), i["nombre"]))
        anterior = selector.value
        selector.set_options(opciones)
        selector.value = anterior if anterior in [valor for _, valor in opciones] else ""

    def _info_activa(self):
        a = red.interfaz_activa()
        w = self.query_one("#info-activa", Static)
        if not a:
            w.update("Sin interfaz activa detectada.")
            return
        txt = f"[b]{a['nombre']}[/b]  ·  IPv4 {a['ipv4'] or '—'}"
        if a.get("ipv6"):
            txt += f"  ·  IPv6 {a['ipv6']}"
        w.update(txt)

    # ---- WIFI (panel fijo) ----
    def _accion_wifi(self):
        self._redes_wifi = []
        self.query_one("#tabla-wifi", DataTable).clear()
        self._boton("btn-wifi", "Escaneando…", "warning")
        self._estado("est-wifi", "Buscando redes WiFi…")
        self._worker_wifi()

    @work(thread=True, exclusive=True, group="wifi")
    def _worker_wifi(self):
        redes, aviso = wifi.escanear()
        exportar.anotar_historial("wifi", "cercanas", f"{len(redes)} redes")
        self._ultimo["wifi"] = ("redes cercanas", redes)
        self.call_from_thread(self._fin_wifi, redes, aviso)

    def _fin_wifi(self, redes, aviso):
        self._boton("btn-wifi", "Escanear WiFi", "primary")
        self._redes_wifi = list(redes)
        tabla = self.query_one("#tabla-wifi", DataTable)
        for r in redes:
            # En la tabla la seguridad va abreviada («WPA2» en vez de «WPA2-Personal»); la
            # completa queda en self._redes_wifi, que es lo que usa «Conectar».
            seg = (r["seguridad"] or "—").replace("-Personal", "").replace("-Enterprise", "-Emp")
            tabla.add_row(r["ssid"] or "(oculta)", _barra(r["senal"]), str(r["senal"]),
                          r["canal"] or "—", seg)
        self.query_one("#panel-wifi").border_title = f"Redes WiFi · {len(redes)}"
        if aviso:
            self._estado("est-wifi", aviso, "aviso")
        else:
            self._estado("est-wifi", f"{len(redes)} redes. Para conectarte: elegí una, escribí la clave y tocá Conectar.",
                         "ok")

    def _accion_conectar(self):
        tabla = self.query_one("#tabla-wifi", DataTable)
        fila = tabla.cursor_row
        if not self._redes_wifi or not 0 <= fila < len(self._redes_wifi):
            self._estado("est-wifi", "Primero tocá «Escanear WiFi» y elegí una red de la lista.", "aviso")
            return
        elegida = self._redes_wifi[fila]
        clave = self.query_one("#in-clave", Input).value
        self._boton("btn-conectar", "Conectando…", "warning")
        self._estado("est-wifi", f"Conectando a {elegida['ssid']}… (puede tardar unos segundos)")
        self._worker_conectar(elegida["ssid"], clave, elegida["seguridad"])

    @work(thread=True, exclusive=True, group="conectar")
    def _worker_conectar(self, ssid, clave, seguridad):
        ok, mensaje = wifi.conectar(ssid, clave, seguridad)     # la clave no se guarda ni se anota
        self.call_from_thread(self._fin_conectar, ok, mensaje)

    def _fin_conectar(self, ok, mensaje):
        self._boton("btn-conectar", "Conectar", "default")
        self.query_one("#in-clave", Input).value = ""           # que la clave no quede a la vista
        self._estado("est-wifi", mensaje, "ok" if ok else "aviso")
        if ok:
            self.set_timer(4, self._cargar_interfaces)          # da tiempo a que llegue la IP

    # ---- DESCUBRIMIENTO ----
    def _accion_descubrir(self):
        rango = self.query_one("#in-rango", Input).value.strip()
        try:
            red.hosts_de(rango)
        except ValueError:
            self._estado("est-desc", f"Rango inválido: '{rango}'. Ejemplo: 192.168.1.0/24", "aviso")
            return
        self.query_one("#tabla-desc", DataTable).clear()
        self._boton("btn-desc", "Escaneando…", "warning")
        self._estado("est-desc", f"Escaneando {rango}…")
        self._worker_descubrir(rango, self._cancel_para("desc"))

    @work(thread=True, exclusive=True, group="desc")
    def _worker_descubrir(self, rango, cancelar):
        def agregar(h):
            self.call_from_thread(self._fila_desc, h)
        hosts, metodo, aviso = descubrimiento.descubrir(rango, al_encontrar=agregar, cancelar=cancelar)
        exportar.anotar_historial("descubrimiento", rango, f"{len(hosts)} hosts ({metodo})")
        self._ultimo["descubrimiento"] = (rango, hosts)
        self.call_from_thread(self._fin_desc, len(hosts), metodo, aviso)

    def _fila_desc(self, h):
        self.query_one("#tabla-desc", DataTable).add_row(
            h["ip"], h["hostname"] or "—", h["mac"] or "—", h["fabricante"] or "—", h["metodo"])

    def _fin_desc(self, n, metodo, aviso):
        self._boton("btn-desc", "Escanear", "primary")
        base = f"Listo: {n} hosts activos (método {metodo}). Elegí uno (Enter) para escanear sus puertos."
        self._estado("est-desc", (base + " " + aviso).strip(), "aviso" if aviso else "ok")

    # ---- PUERTOS ----
    def _accion_puertos(self):
        obj = self.query_one("#in-obj", Input).value.strip()
        if not obj:
            self._estado("est-puertos", "Escribí una IP objetivo.", "aviso")
            return
        modo = self.query_one("#sel-modo", Select).value
        self.query_one("#tabla-puertos", DataTable).clear()
        self._boton("btn-puertos", "Escaneando…", "warning")
        self._estado("est-puertos", f"Escaneando puertos de {obj} (modo {modo})…")
        self._worker_puertos(obj, modo, self._cancel_para("puertos"))

    @work(thread=True, exclusive=True, group="puertos")
    def _worker_puertos(self, obj, modo, cancelar):
        def agregar(p):
            self.call_from_thread(self._fila_puerto, p)
        abiertos = puertos.escanear(obj, modo=modo, con_banner=True, al_encontrar=agregar, cancelar=cancelar)
        so, ttl = puertos.estimar_so(obj)
        exportar.anotar_historial("puertos", obj, f"{len(abiertos)} abiertos, SO≈{so}")
        self._ultimo["puertos"] = (obj, abiertos)
        self.call_from_thread(self._fin_puertos, len(abiertos), so, ttl)

    def _fila_puerto(self, p):
        self.query_one("#tabla-puertos", DataTable).add_row(
            str(p["puerto"]), p["servicio"], p["banner"] or "—")

    def _fin_puertos(self, n, so, ttl):
        self._boton("btn-puertos", "Escanear", "primary")
        extra = f" · SO probable: {so} (TTL {ttl})" if ttl else ""
        self._estado("est-puertos", f"Listo: {n} puertos abiertos.{extra}", "ok")

    def _accion_nmap(self):
        obj = self.query_one("#in-obj", Input).value.strip()
        if not obj:
            self._estado("est-puertos", "Escribí una IP objetivo para nmap.", "aviso")
            return
        self._boton("btn-nmap", "nmap…", "warning")
        self._estado("est-puertos", f"Ejecutando nmap sobre {obj}… (puede tardar)")
        self._worker_nmap(obj)

    @work(thread=True, exclusive=True, group="nmap")
    def _worker_nmap(self, obj):
        filas, error = nmap_.escanear(obj)
        self.call_from_thread(self._fin_nmap, filas, error)

    def _fin_nmap(self, filas, error):
        self._boton("btn-nmap", "nmap", "default")
        if error:
            self._estado("est-puertos", error, "aviso")
            return
        tabla = self.query_one("#tabla-puertos", DataTable)
        tabla.clear()
        for f in filas:
            detalle = " ".join(x for x in (f["producto"], f["version"]) if x) or f["servicio"]
            tabla.add_row(str(f["puerto"]), f["servicio"], detalle or "—")
        obj = self.query_one("#in-obj", Input).value.strip()
        self._ultimo["puertos"] = (obj, filas)
        self._estado("est-puertos", f"nmap: {len(filas)} servicios en {obj}.", "ok")

    # ---- PAQUETES (sniffing) ----
    def _set_filtro(self, proto):
        self._filtro = proto
        for p in PROTOS:
            b = self.query_one(f"#f-{p.lower()}", Button)
            b.variant = "primary" if p == proto else "default"
        self._render_paquetes()

    def _render_paquetes(self):
        tabla = self.query_one("#tabla-paq", DataTable)
        tabla.clear()
        for info in self._paquetes:
            if self._filtro == "TODOS" or info["proto"] == self._filtro:
                self._add_fila_paq(tabla, info)

    def _add_fila_paq(self, tabla, info):
        tabla.add_row(info["hora"], info["proto"], info["origen"] or "—",
                      info["destino"] or "—", str(info["long"]), info["detalle"])

    def _accion_sniff(self):
        if self._sniff and self._sniff.corriendo:
            self._detener_captura()
            return
        ok, motivo = sniffer.Sniffer.disponible()
        if not ok:
            self._estado("est-paq", motivo, "aviso")
            return
        self.query_one("#tabla-paq", DataTable).clear()
        self._paquetes.clear()
        self._origenes.clear()
        filtro = self.query_one("#in-filtro", Input).value.strip()
        self._dns_vistos.clear()
        self._traf_sucio = True
        elegida = self.query_one("#sel-iface", Select).value
        interfaz = elegida if isinstance(elegida, str) and elegida else None      # None = la placa por defecto
        self._sniff = sniffer.Sniffer(al_paquete=lambda info: self.call_from_thread(self._fila_paq, info))
        if self._sniff.arrancar(interfaz=interfaz, filtro=filtro):
            self._sniff_ui(True)
            self._estado("est-paq", "Capturando en vivo… (P pausa · Detener frena)"
                         + (f"  placa: {interfaz}" if interfaz else "")
                         + (f"  filtro: {filtro}" if filtro else ""))
        else:
            self._estado("est-paq", self._sniff.error or "No se pudo iniciar la captura.", "aviso")
            self._sniff = None

    def _sniff_ui(self, capturando):
        """Deja los botones de captura coherentes con el estado."""
        if capturando:
            self._boton("btn-sniff", "Detener", "error")
        else:
            self._boton("btn-sniff", "Capturar", "primary")
        self.query_one("#btn-pausa", Button).disabled = not capturando
        self._boton("btn-pausa", "Pausar", "default")

    def _detener_captura(self):
        self._sniff.frenar()
        self._sniff_ui(False)
        # Para exportar, los paquetes van sin el dato interno de DNS (ya está en «detalle»).
        self._ultimo["paquetes"] = ("captura en vivo",
                                     [{k: v for k, v in p.items() if k != "dns"} for p in self._paquetes])
        self._estado("est-paq", f"Captura detenida. Total: {self._sniff.total} paquetes.", "ok")
        self._traf_sucio = True

    def _accion_pausa(self):
        s = self._sniff
        if not (s and s.corriendo):
            return
        if s.pausado:
            s.reanudar()
            self._boton("btn-pausa", "Pausar", "default")
            self._estado("est-paq", "Capturando en vivo… (P pausa · Detener frena)")
        else:
            s.pausar()
            self._boton("btn-pausa", "Reanudar", "warning")
            self._estado("est-paq", f"En pausa: {s.total} paquetes guardados. Reanudar (P) para seguir.",
                         "aviso")

    def action_pausar(self):
        self._accion_pausa()

    def _fila_paq(self, info):
        if self._sniff is None or self._sniff.detenido:
            return                        # paquetes que llegaron después de frenar
        self._paquetes.append(info)
        if info["origen"]:
            self._origenes[info["origen"]] += 1
        if self._filtro == "TODOS" or info["proto"] == self._filtro:
            tabla = self.query_one("#tabla-paq", DataTable)
            self._add_fila_paq(tabla, info)
            if tabla.row_count > 500:
                tabla.remove_row(list(tabla.rows)[0])
        if info.get("dns"):
            self._registrar_dns(info["dns"])
        self._traf_sucio = True
        c = self._sniff.conteo
        self._estado("est-paq", f"Total {self._sniff.total} · TCP {c['TCP']} · UDP {c['UDP']} · "
                     f"ICMP {c['ICMP']} · ICMP6 {c['ICMP6']} · ARP {c['ARP']}")

    # ---- TRÁFICO ----
    def _registrar_dns(self, dns):
        """Anota un DNS visto en la red: qué nombre se pidió, qué se respondió y cuántas veces."""
        reg = self._dns_vistos.setdefault((dns["nombre"], dns["tipo"]), {"resp": [], "veces": 0})
        if dns["qr"] == "consulta" or reg["veces"] == 0:
            reg["veces"] += 1
        for r in dns["respuestas"]:
            if r not in reg["resp"]:
                reg["resp"].append(r)

    def _vigilar_captura(self):
        """Si el hilo de captura murió por un error (falta Npcap, la placa no existe…),
        lo avisa. Si no, la pantalla seguiría diciendo «Capturando…» sin que llegue nada."""
        s = self._sniff
        if s is not None and not s.detenido and not s.corriendo and s.error:
            s.frenar()
            self._sniff_ui(False)
            self._estado("est-paq", "La captura se cortó: " + s.error, "aviso")

    def _refrescar_trafico(self):
        """Corre una vez por segundo y redibuja solo si hubo novedades, para no
        reconstruir las tablas con cada paquete."""
        try:
            self._vigilar_captura()
        except NoMatches:
            return                            # la pantalla ya se está cerrando
        if not self._traf_sucio:
            return
        self._traf_sucio = False
        try:
            self._actualizar_trafico()
        except NoMatches:
            pass                          # la pantalla ya se está cerrando

    def _actualizar_trafico(self):
        if not self._sniff:
            return
        total = max(self._sniff.total, 1)
        tp = self.query_one("#tabla-traf", DataTable)
        tp.clear()
        for proto, n in self._sniff.conteo.items():
            tp.add_row(proto, str(n), f"{round(n * 100 / total)}%")
        tt = self.query_one("#tabla-top", DataTable)
        tt.clear()
        for ip, n in self._origenes.most_common(12):
            tt.add_row(ip or "—", str(n))
        td = self.query_one("#tabla-dnsv", DataTable)
        td.clear()
        vistos = sorted(self._dns_vistos.items(), key=lambda kv: (-kv[1]["veces"], kv[0]))
        for (nombre, tipo), reg in vistos[:60]:
            resp = ", ".join(reg["resp"]) or "—"
            td.add_row(nombre, tipo, resp if len(resp) <= 60 else resp[:59] + "…", str(reg["veces"]))

    # ---- DNS ----
    def _accion_dns(self):
        nombre = self.query_one("#in-dns", Input).value.strip()
        if not nombre:
            self._estado("est-dns", "Escribí un dominio o una IP.", "aviso")
            return
        tipo = self.query_one("#sel-tipo", Select).value
        servidor = self.query_one("#sel-dns", Select).value
        self.query_one("#tabla-dns", DataTable).clear()
        self._boton("btn-dns", "Consultando…", "warning")
        self._estado("est-dns", f"Consultando {tipo} de {nombre}…")
        self._worker_dns(nombre, tipo, servidor)

    @work(thread=True, exclusive=True, group="dns")
    def _worker_dns(self, nombre, tipo, servidor):
        registros, error = dns_.consultar(nombre, tipo, servidor)
        exportar.anotar_historial("dns", f"{tipo} {nombre}", f"{len(registros)} registros")
        self._ultimo["dns"] = (f"{tipo} {nombre}", registros)
        self.call_from_thread(self._fin_dns, tipo, nombre, registros, error)

    def _fin_dns(self, tipo, nombre, registros, error):
        self._boton("btn-dns", "Consultar", "primary")
        tabla = self.query_one("#tabla-dns", DataTable)
        for reg in registros:
            tabla.add_row(tipo, reg)
        if error:
            self._estado("est-dns", error, "aviso")
        else:
            self._estado("est-dns", f"{len(registros)} registro(s) {tipo} de {nombre}.", "ok")

    # ---- CONSOLA (comandos de red seguros, menú fijo) ----
    def _actualizar_ayuda_consola(self):
        entrada = consola.buscar(self.query_one("#sel-cmd", Select).value)
        if not entrada:
            return
        txt, clase = entrada["desc"], ""
        if not entrada["disponible"]:
            txt += f"  ·  ⚠ '{entrada['programa']}' no está instalado en este sistema."
            clase = "aviso"
        elif entrada["objetivo"]:
            txt += "  ·  necesita un objetivo (IP o host)."
        self._estado("est-cmd", txt, clase)

    def _accion_consola(self):
        id_cmd = self.query_one("#sel-cmd", Select).value
        objetivo = self.query_one("#in-cmd-obj", Input).value.strip()
        self._boton("btn-cmd", "Ejecutando…", "warning")
        self._estado("est-cmd", "Ejecutando…")
        self._worker_consola(id_cmd, objetivo)

    @work(thread=True, exclusive=True, group="consola")
    def _worker_consola(self, id_cmd, objetivo):
        salida, error = consola.ejecutar(id_cmd, objetivo)
        self.call_from_thread(self._fin_consola, id_cmd, objetivo, salida, error)

    def _fin_consola(self, id_cmd, objetivo, salida, error):
        self._boton("btn-cmd", "Ejecutar", "primary")
        if error:
            self._estado("est-cmd", error, "aviso")
            return
        log = self.query_one("#log-cmd", RichLog)
        log.write(f"$ {id_cmd}" + (f" {objetivo}" if objetivo else ""))
        log.write(salida or "(sin salida)")
        log.write("")
        self._ultimo["consola"] = (f"{id_cmd} {objetivo}".strip(), (salida or "").splitlines())
        self._estado("est-cmd", "Listo.", "ok")

    # ---- selección en tablas: encadenar los escaneos ----
    def on_data_table_row_selected(self, evento: DataTable.RowSelected):
        tabla = evento.data_table
        if tabla.id == "tabla-desc":
            ip = str(tabla.get_row(evento.row_key)[0]).strip()
            if not ip or ip == "—":
                return
            self.query_one("#in-obj", Input).value = ip
            self.query_one(TabbedContent).active = "tab-puertos"
            self._estado("est-puertos", f"Objetivo {ip} (elegido del descubrimiento). Escaneando…")
            self._accion_puertos()
        elif tabla.id == "tabla-if":
            ipv4 = str(tabla.get_row(evento.row_key)[1]).strip()
            try:
                ipaddress.ip_address(ipv4)
            except ValueError:
                self.notify("Esa interfaz no tiene IPv4; elegí una con IP para escanear su red.",
                            severity="warning", timeout=3)
                return
            if ipv4.startswith("169.254."):
                self.notify("Esa placa no consiguió una IP (169.254.x.x): no está conectada a una red, o la "
                            "red no le dio una dirección. Si es la WiFi, elegí una red en «Redes WiFi» "
                            "y tocá Conectar.", severity="warning", timeout=8)
                return
            rango = red.rango_local(ipv4)
            self.query_one("#in-rango", Input).value = rango
            self.query_one(TabbedContent).active = "tab-desc"
            self._estado("est-desc", f"Rango {rango} (de la interfaz elegida). Tocá «Escanear».")

    def on_select_changed(self, evento: Select.Changed):
        if evento.select.id == "sel-cmd":
            self._actualizar_ayuda_consola()

    # ---- EXPORTAR ----
    def _exportar(self, formato):
        if not self._ultimo:
            self._estado("est-exp", "Todavía no hay resultados para guardar. Hacé un escaneo primero.", "aviso")
            return
        tipo = list(self._ultimo)[-1]
        objetivo, datos = self._ultimo[tipo]
        try:
            if formato == "json":
                ruta = exportar.guardar_json(tipo, objetivo, datos)
            elif formato == "csv":
                ruta = exportar.guardar_csv(tipo, objetivo, datos)
            else:
                lineas = [str(d) for d in datos] or ["(sin resultados)"]
                ruta = exportar.guardar_txt(tipo, objetivo, lineas)
        except OSError as e:
            self._estado("est-exp", f"No se pudo guardar: {e}", "aviso")
            return
        try:
            mostrar = os.path.relpath(ruta)      # «resultados/paquetes-….csv», más corto que la ruta entera
        except ValueError:                       # en Windows, si está en otro disco
            mostrar = ruta
        self._estado("est-exp", f"Guardado: {mostrar}", "ok")


def main():
    NetScanner().run()


if __name__ == "__main__":
    main()
