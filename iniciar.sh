#!/usr/bin/env bash
# Prepara el entorno la primera vez y arranca NetScanner.
#   ./iniciar.sh           (funciones básicas, sin permisos especiales)
#   sudo ./iniciar.sh      (suma ARP, MAC/fabricante, captura de paquetes y Tráfico)
set -euo pipefail
cd "$(dirname "$0")"

# Windows no distingue mayúsculas, Python sí: la carpeta del programa tiene que llamarse
# "netscanner" en minúsculas. Si quedó como "NetScanner" (pasa al mezclar carpetas al
# descomprimir, y se ve desde WSL en una carpeta de Windows), la corregimos.
existe=0
alternativa=""
for f in *; do
    minus=$(printf '%s' "$f" | tr 'A-Z' 'a-z')
    if [ "$f" = "netscanner" ]; then
        existe=1
    elif [ "$minus" = "netscanner" ] && [ -f "$f/__main__.py" ]; then
        alternativa="$f"
    fi
done
if [ "$existe" = 0 ] && [ -n "$alternativa" ]; then
    echo "La carpeta del programa se llama '$alternativa' y tiene que ser 'netscanner' (en minúsculas). La corrijo..."
    mv "$alternativa" netscanner_tmp_
    mv netscanner_tmp_ netscanner
fi

# El programa (la carpeta netscanner) tiene que estar al lado de este archivo.
if [ ! -f netscanner/__main__.py ]; then
    if [ -f NetScanner/netscanner/__main__.py ]; then
        echo "El programa está en la carpeta NetScanner/ de adentro. Sigo desde ahí."
        cd NetScanner
        exec bash ./iniciar.sh "$@"
    fi
    echo "No encuentro la carpeta 'netscanner' junto a iniciar.sh."
    echo "Descomprimí TODO el ZIP y corré iniciar.sh desde la carpeta que tenga a la vez"
    echo "iniciar.sh y la carpeta netscanner. Carpeta actual: $(pwd)"
    exit 1
fi

PY=python3
command -v "$PY" >/dev/null || { echo "Falta Python 3. Instalalo desde https://python.org"; exit 1; }
"$PY" -c 'import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)' || { echo "Hace falta Python 3.8 o más nuevo."; exit 1; }

# Un venv NO es portable entre sistemas. Si el .venv existe pero no tiene el
# python de Linux (p.ej. lo creó Windows en una carpeta compartida por WSL),
# lo rehacemos para este sistema.
if [ -d .venv ] && [ ! -x .venv/bin/python ]; then
    echo "El entorno .venv existente no es de Linux (¿lo creó Windows?). Lo rehago para este sistema..."
    rm -rf .venv
fi

# El archivo .venv/.instalado se crea recién cuando la instalación termina bien.
# Si falta (entorno nuevo, o una instalación que se cortó), (re)instalamos.
if [ ! -x .venv/bin/python ] || [ ! -f .venv/.instalado ]; then
    echo "Preparando el entorno por primera vez (puede tardar uno o dos minutos; no lo cortes)..."
    if [ ! -d .venv ] && ! "$PY" -m venv .venv; then
        rm -rf .venv
        echo
        echo "No pude crear el entorno de Python. En Debian, Ubuntu y Kali falta un paquete:"
        echo "    sudo apt install python3-venv python3-pip"
        echo "Instalalo y volvé a correr ./iniciar.sh"
        exit 1
    fi
    .venv/bin/python -m pip install --upgrade pip || true      # actualizar pip es opcional
    if ! .venv/bin/python -m pip install -r requirements.txt; then
        echo
        echo "No se pudieron instalar las librerías. Revisá tu conexión a internet"
        echo "y volvé a correr ./iniciar.sh (retoma donde quedó)."
        exit 1
    fi
    touch .venv/.instalado
    # Con sudo, el entorno tiene que seguir siendo tuyo y no de root; si no,
    # después no podrías actualizarlo ni borrarlo con tu usuario.
    if [ "$(id -u)" = 0 ] && [ -n "${SUDO_UID:-}" ]; then
        chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" .venv 2>/dev/null || true
    fi
    echo "Entorno listo."
fi
exec .venv/bin/python -m netscanner "$@"
