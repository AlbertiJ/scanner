@echo off
REM Prepara el entorno la primera vez y arranca NetScanner.
REM Para las funciones que necesitan permisos (ARP, captura de paquetes),
REM hace clic derecho en este archivo y elige "Ejecutar como administrador".
cd /d "%~dp0"

REM Windows no distingue mayusculas de minusculas, pero Python si: la carpeta del
REM programa tiene que llamarse "netscanner" en minusculas. Si quedo como "NetScanner"
REM (pasa al mezclar carpetas cuando se descomprime), la corregimos.
if exist "netscanner\__main__.py" (
    dir /b /ad | findstr /x /c:"netscanner" >nul
    if errorlevel 1 (
        echo La carpeta del programa tiene mayusculas y Python la necesita en minusculas. La corrijo...
        ren "netscanner" "netscanner_tmp_"
        ren "netscanner_tmp_" "netscanner"
        dir /b /ad | findstr /x /c:"netscanner" >nul
        if errorlevel 1 (
            echo No pude renombrarla. Cambiale el nombre a mano a: netscanner
            pause
            exit /b 1
        )
    )
)

REM El programa (la carpeta netscanner) tiene que estar al lado de este archivo.
if exist "netscanner\__main__.py" goto :hay_programa
if exist "NetScanner\netscanner\__main__.py" (
    echo El programa esta en la carpeta NetScanner de adentro. Sigo desde ahi.
    cd /d "NetScanner"
    call iniciar.bat %*
    exit /b
)
echo.
echo No encuentro la carpeta "netscanner" junto a iniciar.bat.
echo Descomprimi TODO el ZIP y corre iniciar.bat desde la carpeta que tenga
echo a la vez iniciar.bat y la carpeta netscanner.
echo Carpeta actual: %cd%
pause
exit /b 1

:hay_programa
where python >nul 2>nul
if errorlevel 1 (
    echo Falta Python 3. Instalalo desde https://python.org y marca "Add Python to PATH".
    pause
    exit /b 1
)

REM Un venv NO es portable entre sistemas. Si el .venv existe pero no tiene el
REM python de Windows (p.ej. lo creo Linux/WSL), lo rehacemos para Windows.
if exist ".venv" if not exist ".venv\Scripts\python.exe" (
    echo El entorno .venv existente no es de Windows. Lo rehago para este sistema...
    rmdir /s /q .venv
)

REM El archivo .venv\.instalado se crea SOLO cuando la instalacion termina bien.
if exist ".venv\.instalado" if exist ".venv\Scripts\python.exe" goto :run

echo Preparando el entorno por primera vez ^(puede tardar uno o dos minutos; NO cierres la ventana^)...
if not exist ".venv" python -m venv .venv
.venv\Scripts\python -m pip install --upgrade pip
.venv\Scripts\python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo ERROR: no se pudieron instalar las librerias. Revisa tu conexion a internet
    echo y volve a correr iniciar.bat ^(la descarga se reintenta sola^).
    pause
    exit /b 1
)
type nul > ".venv\.instalado"
echo Entorno listo.

:run
.venv\Scripts\python -m netscanner %*
if errorlevel 1 (
    echo.
    echo Si el mensaje dice "No module named netscanner", mira la tabla "Si algo falla" del README.
)
pause
