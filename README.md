# NetScanner

**Escáner de red con interfaz de terminal (TUI), en español y multiplataforma (Windows y Linux).**

Unifica en una sola herramienta de Python las funciones de tres proyectos de escaneo de red, con el **panel de una sola pantalla** del [netscanner de Chleba](https://github.com/Chleba/netscanner) reconstruido en Python: arriba, siempre a la vista, las redes WiFi y las interfaces; abajo, las pestañas de trabajo.

> ⚠️ **Usá esta herramienta solo en redes propias o donde tengas autorización expresa.** Escanear redes ajenas puede ser ilegal.

---

## Qué hace

Es un **panel (dashboard) de una sola pantalla**, como el netscanner original.

**Arriba, siempre visible:**

| Panel | Para qué sirve |
|---|---|
| **Redes WiFi** | Redes cercanas con su señal, canal y seguridad. Elegí una, escribí la clave (si tiene) y tocá **Conectar**. |
| **Interfaces** | Las placas de red de la máquina, con **IPv4, IPv6, MAC** y estado. Marca la activa. **Elegí una** (Enter o clic) y salta a Descubrimiento con el rango de su red cargado. |
| **Interfaz activa** | La placa por la que sale tu tráfico, con su IPv4/IPv6. |

**Abajo, en pestañas:**

| Pestaña | Para qué sirve |
|---|---|
| **Descubrimiento** | Encuentra los equipos vivos en la red. Con permisos usa ARP y muestra MAC + fabricante (OUI); sin permisos, ping. **Elegí un host** y salta a Puertos escaneándolo. |
| **Puertos** | Escanea los puertos TCP de un equipo, lee el *banner* y estima el sistema operativo. Opción **nmap** si está instalado. |
| **Paquetes** | Captura el tráfico en vivo (TCP, UDP, ICMP, ARP e **ICMP6/IPv6**) con **filtro por protocolo** (Todos/ARP/TCP/UDP/ICMP/ICMP6) y filtro BPF opcional. **Pausar/Reanudar** (botón o tecla `p`) sin perder lo capturado. Necesita administrador. |
| **Tráfico** | Mientras capturás: conteo por protocolo, **top de orígenes** y los **DNS que pasan por la red** (qué nombre se pidió, qué se respondió y cuántas veces; los «no existe» se marcan). Solo se ven los DNS sin cifrar (puerto 53 y mDNS): DNS sobre HTTPS o TLS viaja cifrado. |
| **DNS** | Registros DNS (A, AAAA, MX, NS, TXT, CNAME, SOA) e inverso (PTR), contra el DNS del sistema o uno que elijas (Google, Cloudflare, Quad9). Usa `dnspython`. |
| **Consola** | Menú **fijo** de comandos de red (ARP, ruteo, interfaces, conexiones, ping, traceroute, nslookup, dig), ejecutados de forma segura. No es una terminal abierta: no hay inyección de comandos posible. |

**Abajo del todo:** barra de **Exportar** el último resultado en **JSON, CSV o TXT** (se guarda en la carpeta `resultados/`).

### Flujo encadenado

De arriba hacia abajo, sin recopiar IPs a mano:

**Interfaces** (elegís una placa) → **Descubrimiento** (rango cargado, escaneás) → elegís un equipo → **Puertos** (lo escanea solo).

### Conectarte a una red WiFi

Para escanear una red WiFi, la placa WiFi tiene que estar conectada a ella. En el panel **Redes WiFi**:

1. Tocá **Escanear WiFi** y elegí una red de la lista (flechas o clic).
2. Escribí la clave en el campo (vacío si la red es abierta) y tocá **Conectar**.
3. Cuando diga «Conectado», elegí la placa WiFi en **Interfaces** (Enter): carga el rango de esa red en Descubrimiento.

Cosas que conviene saber:

- Una placa con IP `169.254.x.x` no consiguió una dirección: o no está conectada a ninguna red, o la red no se la dio. El estado dice «sin IP» y el programa avisa, en vez de escanear ese rango vacío.
- La captura de paquetes usa la placa que elijas en el selector **Placa** de la pestaña Paquetes. En «automática» usa la placa por defecto, que suele ser la de la LAN. Para capturar por WiFi, elegí la placa Wi-Fi.
- La clave no se guarda ni se anota en el historial, y se borra del campo al terminar. Windows sí guarda el perfil de la red, igual que cuando te conectás desde su menú: se olvida en Configuración → Red e Internet → Wi-Fi → Administrar redes conocidas.
- Si una red abierta te pide «iniciar sesión» en una página (portal cautivo: hoteles, bares, aeropuertos), eso se hace en el navegador. Desde acá no se puede.
- Las redes ocultas, las de empresa (WPA-Enterprise) y las WEP no se conectan desde acá: usá el menú WiFi del sistema.
- Conectate solo a redes tuyas o públicas que puedas usar. Una red abierta que no conocés puede ser una trampa: no mandes datos sensibles por ahí.

### Seguridad de la pestaña Consola

La pestaña *Consola* **no** es una terminal donde escribís lo que quieras. Es un
catálogo cerrado de comandos conocidos, con tres barreras contra la **inyección
de comandos**: el nombre del programa sale del catálogo (no del usuario), se
ejecuta con `subprocess` y lista de argumentos (`shell=False`, sin shell de por
medio), y el objetivo de `ping`/`traceroute`/etc. se valida como IP o nombre de
host antes de correr. Así, aunque alguien escriba algo con `;` o `|`, no se
ejecuta como comando.

---

## Instalación y uso

No necesitás saber programar. Solo hace falta **Python 3.8 o más nuevo** ([python.org](https://python.org)).

### Windows

**Lo más simple: el instalador.** Descomprimir a mano suele salir mal en Windows (las carpetas quedan anidadas o se fusionan con otro nombre), así que hay un instalador que lo hace bien:

1. Bajá `NetScanner.zip` y los dos archivos del instalador, `Instalar-NetScanner.bat` e `Instalar-NetScanner.ps1`, a la misma carpeta (por ejemplo Descargas).
2. Hacé doble clic en **`Instalar-NetScanner.bat`**.

Descomprime el ZIP, lo instala en una carpeta `NetScanner` en la raíz del disco del sistema, conserva tu entorno y tus resultados si ya tenías una instalación, y arranca el programa. Para actualizar más adelante: bajá el ZIP nuevo y volvé a correr el instalador (también queda dentro de esa carpeta). El `.ps1` es un archivo de texto: podés leerlo antes de correrlo, y el permiso «Bypass» que usa el `.bat` vale solo para esa ejecución.

**A mano:** clic derecho en el ZIP → **Extraer todo…** y, en el destino, borrá el `NetScanner` que Windows agrega al final de la ruta (así no queda una carpeta de más). Después, doble clic en **`iniciar.bat`**.

- Para las funciones con permisos (ARP, captura de paquetes): clic derecho en `iniciar.bat` → **Ejecutar como administrador**. Además, para la captura hace falta [Npcap](https://npcap.com).

### Linux / macOS
1. Descargá y descomprimí esta carpeta.
2. En una terminal, dentro de la carpeta:
   ```bash
   ./iniciar.sh
   ```
   - Para todas las funciones (ARP, MAC/fabricante, captura de paquetes, Tráfico):
     ```bash
     sudo ./iniciar.sh
     ```
   - **Debian, Ubuntu y Kali:** si el lanzador dice que no pudo crear el entorno, falta un paquete:
     ```bash
     sudo apt install python3-venv python3-pip
     ```
   - Si `./iniciar.sh` responde «Permission denied», dale permiso de ejecución: `chmod +x iniciar.sh`.

La primera vez, el lanzador arma solo un entorno de Python (carpeta `.venv`) e instala lo que necesita. Dejalo terminar, sin cortarlo con Ctrl+C. Las veces siguientes arranca directo. Si usás `sudo`, el entorno y la carpeta `resultados/` quedan a nombre de tu usuario, no de root.

**Un entorno no se comparte entre sistemas.** Si la misma carpeta se usa desde Windows y desde Linux (por ejemplo, desde WSL, dentro de una carpeta de Windows), cada lanzador detecta el entorno del otro sistema y lo rehace. Conviene una copia de la carpeta para cada sistema: en Linux, dentro de tu home (`~/NetScanner`).

### WSL (Linux dentro de Windows)

Anda, pero con límites que vienen de WSL y no del programa:

- **Descubrimiento:** WSL2 suele darte una red virtual (NAT). Vas a ver los equipos de esa red y no los de tu casa u oficina. El programa lo avisa en pantalla. Para escanear tu red real usá Windows o un Linux instalado en la máquina.
- **WiFi:** WSL no ve las placas WiFi de Windows.
- **Captura de paquetes y Tráfico:** solo ven el tráfico de la red virtual de WSL.
- **Interfaces, Puertos, DNS y Consola** funcionan normal.

### Manejo
- Se mueve con el **teclado** (Tab entre pestañas, flechas en las tablas) y también con el **mouse**.
- `q` sale · `d` cambia el tema · `p` pausa o reanuda la captura · `Esc` cancela un escaneo en curso.
- La tecla `p` no responde mientras escribís en un campo de texto: hacé clic en una tabla y volvé a probar.

### Si algo falla

| Mensaje | Qué pasó | Qué hacer |
|---|---|---|
| `No module named netscanner`, o «No encuentro la carpeta netscanner» | El lanzador quedó separado de la carpeta `netscanner`, o el ZIP se descomprimió dentro de otra carpeta. | Corré el lanzador desde la carpeta que tenga **a la vez** `iniciar.bat` (o `iniciar.sh`) y la carpeta `netscanner`. En PowerShell: `Expand-Archive .\NetScanner.zip -DestinationPath .\Prueba` y entrá a `.\Prueba\NetScanner`. Si quedó una carpeta `NetScanner` adentro, el lanzador sigue solo desde ella. |
| `No module named netscanner` y la carpeta del programa se llama `NetScanner` (con mayúsculas) | Windows no distingue mayúsculas, pero Python sí. Pasa al mezclar carpetas cuando se descomprime: Windows fusiona la carpeta del programa con otra llamada igual y le deja ese nombre. | El lanzador nuevo lo corrige solo. A mano, en PowerShell: `Rename-Item NetScanner netscanner_tmp` y después `Rename-Item netscanner_tmp netscanner`. |
| `No module named textual` (u otra librería) | La instalación se cortó a la mitad (Ctrl+C o ventana cerrada). | Volvé a correr el lanzador: retoma solo. Dejalo terminar. |
| `Permission denied` (Linux) | El archivo perdió el permiso de ejecución. | `chmod +x iniciar.sh` |
| «No pude crear el entorno» (Debian, Ubuntu, Kali) | Falta un paquete de Python. | `sudo apt install python3-venv python3-pip` |

---

## Permisos: qué anda con y sin administrador

| Función | Sin permisos | Con administrador |
|---|---|---|
| Interfaces, Puertos, WiFi, DNS, Consola, nmap básico | ✅ | ✅ |
| Descubrimiento por **ping** | ✅ | ✅ |
| Descubrimiento por **ARP** (trae MAC + fabricante) | — | ✅ |
| **Captura de paquetes** (sniffing) | — | ✅ (+ Npcap en Windows) |

El programa avisa en pantalla cuando una función necesita permisos que no tiene, y sigue funcionando con lo demás.

---

## Requisitos opcionales

- **nmap**: para el escaneo profundo de la pestaña Puertos. En Linux: `sudo apt install nmap`. En Windows: [nmap.org](https://nmap.org).
- **Comandos de la pestaña Consola** (Linux): `ip`, `ss`, `ping`, `traceroute`, `dig` y `nslookup`. En Debian, Ubuntu y Kali: `sudo apt install iputils-ping traceroute dnsutils`. Si falta alguno, la pestaña lo avisa y el resto sigue andando.
- **WiFi** (Linux): usa `nmcli` (NetworkManager). Si no está, prueba con `iw`, que necesita `sudo`.
- **Npcap** (solo Windows): para la captura de paquetes. [npcap.com](https://npcap.com).

---

## Créditos

Este proyecto reúne y reconstruye el trabajo de tres repositorios:

- **[Chleba/netscanner](https://github.com/Chleba/netscanner)** (MIT) — la interfaz de pestañas original (en Rust), reconstruida acá en Python con Textual.
- **[anishalx/netscanner](https://github.com/anishalx/netscanner)** (MIT) — base de datos de fabricantes (OUI) y enfoque de descubrimiento ARP/ICMP con Scapy.
- **[soulstep29/Netscanner](https://github.com/soulstep29/Netscanner)** — funciones de escaneo (ping sweep, puertos, banner, nmap) que sirvieron de referencia.

La base de fabricantes proviene de la [IEEE OUI Registry](https://standards.ieee.org/products-programs/regauth/oui/). Ver `CREDITOS.md` para el detalle.

Licencia: MIT (ver `LICENSE`).
