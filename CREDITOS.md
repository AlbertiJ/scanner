# Créditos y atribuciones

NetScanner unifica y reconstruye el trabajo de tres proyectos de código abierto.

## Chleba/netscanner — la interfaz
- https://github.com/Chleba/netscanner
- Licencia: MIT
- Aporte: el diseño de la interfaz de pestañas (Interfaces, Descubrimiento, Puertos,
  WiFi, Paquetes/Sniffing, Exportar). El original está en Rust; acá se reconstruyó
  en Python con la librería Textual, respetando la disposición y las secciones.

## anishalx/netscanner — datos y técnicas de descubrimiento
- https://github.com/anishalx/netscanner
- Licencia: MIT
- Aporte: la base de datos de fabricantes `datos/oui.csv.gz` (usada tal cual) y el
  enfoque de descubrimiento por ARP e ICMP con Scapy, con manejo prolijo de la
  falta de privilegios / Npcap.

## soulstep29/Netscanner — funciones de escaneo (referencia)
- https://github.com/soulstep29/Netscanner
- Sin archivo de licencia publicado al momento de escribir esto.
- Aporte: sirvió de referencia para las funciones de barrido por ping, escaneo de
  puertos, captura de banner e integración con nmap, ya orientadas al español. El
  código de NetScanner es una reimplementación propia inspirada en esas ideas.

## Base de fabricantes (OUI)
- Fuente: IEEE MA-L OUI Registry
- https://standards.ieee.org/products-programs/regauth/oui/
- El archivo `netscanner/datos/oui.csv.gz` es una copia de esa base pública
  (~40.000 asignaciones), tomada del repositorio anishalx/netscanner.

## Librerías de terceros
- Textual y Rich (interfaz de terminal) — MIT
- Scapy (paquetes de red) — GPLv2
- psutil (interfaces) — BSD-3
- python-nmap (integración nmap) — GPLv3
- dnspython (consultas DNS) — ISC
