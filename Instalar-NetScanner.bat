@echo off
REM Instala o actualiza NetScanner con el ZIP mas nuevo y lo arranca.
REM No hace falta descomprimir nada a mano: busca el ZIP junto a este archivo o en Descargas
REM y lo instala en una carpeta NetScanner en la raiz del disco, conservando tu entorno y tus resultados.
REM El trabajo lo hace Instalar-NetScanner.ps1, que es de texto: podes leerlo antes de correrlo.
REM El permiso "Bypass" vale solo para esta ejecucion; no cambia la configuracion de Windows.
if not exist "%~dp0Instalar-NetScanner.ps1" (
    echo No encuentro Instalar-NetScanner.ps1 junto a este archivo.
    echo Bajalos los dos y ponelos en la misma carpeta.
    pause
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Instalar-NetScanner.ps1" %*
if errorlevel 1 pause
