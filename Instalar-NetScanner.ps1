<#
.SYNOPSIS
  Instala o actualiza NetScanner a partir del ZIP y lo arranca. No hay que descomprimir nada a mano.

.DESCRIPTION
  Descomprimir a mano suele salir mal: Windows anida las carpetas (NetScanner\NetScanner) y,
  al subir los archivos un nivel, fusiona la carpeta del programa con otra llamada igual y le
  cambia las mayusculas. Python distingue mayusculas y ya no encuentra el programa.

  Este script hace lo que harias a mano, pero bien:
    1. Busca el ZIP mas nuevo: el que le pases con -Zip, el que este junto a este script,
       o el de la carpeta Descargas.
    2. Lo descomprime en una carpeta temporal.
    3. Ubica el programa adentro, aunque el ZIP tenga carpetas de mas.
    4. Lo copia a la carpeta de destino, conservando tu entorno (.venv) y tus resultados.
    5. Arranca NetScanner.

  No pide permisos de administrador. Solo escribe en la carpeta de destino y en una carpeta
  temporal que borra al terminar. Es un archivo de texto: podes leerlo antes de correrlo.

.PARAMETER Zip
  Ruta del ZIP. Si se omite, busca NetScanner*.zip junto a este script y en Descargas.

.PARAMETER Destino
  Carpeta donde instalar. Por defecto, la carpeta NetScanner en la raiz del disco del sistema (en Linux o macOS, NetScanner dentro de tu carpeta personal).

.PARAMETER NoIniciar
  Instala pero no arranca el programa.

.EXAMPLE
  .\Instalar-NetScanner.ps1
#>
param(
    [string]$Zip = '',
    [string]$Destino = '',
    [switch]$NoIniciar
)

$ErrorActionPreference = 'Stop'
$esWindows = ($env:OS -eq 'Windows_NT')
$tmp = $null

function Decir([string]$texto, [string]$color = 'Gray') {
    Write-Host $texto -ForegroundColor $color
}

function Carpeta-Descargas {
    if ($esWindows) {
        # La carpeta Descargas puede estar movida (por ejemplo a OneDrive): se la pedimos a Windows.
        try {
            $ruta = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
            if ($ruta -and (Test-Path -LiteralPath $ruta)) { return $ruta }
        } catch { }
    }
    foreach ($nombre in 'Downloads', 'Descargas') {
        $ruta = Join-Path $HOME $nombre
        if (Test-Path -LiteralPath $ruta) { return $ruta }
    }
    return $null
}

function Zip-Mas-Nuevo($carpeta) {
    if (-not $carpeta -or -not (Test-Path -LiteralPath $carpeta)) { return $null }
    return Get-ChildItem -LiteralPath $carpeta -Filter 'NetScanner*.zip' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
}

try {
    if ($PSScriptRoot) { $aqui = $PSScriptRoot } else { $aqui = (Get-Location).Path }

    # 1) El ZIP
    if ($Zip) {
        if (-not (Test-Path -LiteralPath $Zip)) { throw "No existe el archivo: $Zip" }
        $archivoZip = Get-Item -LiteralPath $Zip
    } else {
        $archivoZip = Zip-Mas-Nuevo $aqui
        if (-not $archivoZip) { $archivoZip = Zip-Mas-Nuevo (Carpeta-Descargas) }
        if (-not $archivoZip) {
            throw 'No encontre NetScanner.zip ni junto a este script ni en Descargas. Bajalo de nuevo y volve a correr esto.'
        }
    }
    Decir ('ZIP: ' + $archivoZip.FullName)

    # 2) La carpeta de destino
    $destinoElegido = [bool]$Destino
    if (-not $Destino) {
        if ($esWindows) { $Destino = 'C:\NetScanner' } else { $Destino = Join-Path $HOME 'NetScanner' }
    }
    try {
        New-Item -ItemType Directory -Path $Destino -Force | Out-Null
    } catch {
        if ($destinoElegido -or -not $esWindows) { throw }
        $Destino = Join-Path $env:USERPROFILE 'NetScanner'
        Decir ('No pude crear la carpeta en C:\. Uso: ' + $Destino) 'Yellow'
        New-Item -ItemType Directory -Path $Destino -Force | Out-Null
    }
    $Destino = (Resolve-Path -LiteralPath $Destino).Path

    # 3) Descomprimir en una carpeta temporal, limpia
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('NetScanner_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    Decir 'Descomprimiendo...'
    Expand-Archive -LiteralPath $archivoZip.FullName -DestinationPath $tmp -Force

    # 4) Ubicar el programa adentro, aunque el ZIP tenga carpetas de mas
    $principal = Get-ChildItem -LiteralPath $tmp -Recurse -Filter '__main__.py' -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Directory.Name -ieq 'netscanner' -and
            (Test-Path -LiteralPath (Join-Path $_.Directory.Parent.FullName 'iniciar.bat'))
        } | Select-Object -First 1
    if (-not $principal) {
        throw 'Ese ZIP no trae NetScanner: no encuentro netscanner\__main__.py junto a iniciar.bat.'
    }
    $raiz = $principal.Directory.Parent.FullName

    # 5) Dejar libre el lugar del programa. Una carpeta vieja llamada "netscanner" (con cualquier
    #    combinacion de mayusculas) se reemplaza si es el programa, o se aparta si es otra cosa.
    #    Asi Windows no la fusiona con la nueva ni le deja el nombre equivocado.
    $viejas = @(Get-ChildItem -LiteralPath $Destino -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -ieq 'netscanner' })
    foreach ($vieja in $viejas) {
        if (Test-Path -LiteralPath (Join-Path $vieja.FullName '__main__.py')) {
            Remove-Item -LiteralPath $vieja.FullName -Recurse -Force
        } else {
            $aparte = '{0}_anterior_{1}' -f $vieja.Name, (Get-Date -Format 'yyyyMMdd-HHmmss')
            Rename-Item -LiteralPath $vieja.FullName -NewName $aparte
            Decir ('Aparte una carpeta vieja (no la borre): ' + $aparte) 'Yellow'
        }
    }

    # 6) Copiar. Si este script corre desde la carpeta de destino, no se pisa a si mismo.
    $propios = @('Instalar-NetScanner.bat', 'Instalar-NetScanner.ps1')
    $desdeDestino = ($aqui.TrimEnd('\', '/') -ieq $Destino.TrimEnd('\', '/'))
    Decir ('Copiando a ' + $Destino + ' ...')
    foreach ($item in Get-ChildItem -LiteralPath $raiz -Force) {
        if ($desdeDestino -and ($propios -contains $item.Name)) { continue }
        Copy-Item -LiteralPath $item.FullName -Destination $Destino -Recurse -Force
    }

    $version = ''
    $init = Join-Path (Join-Path $Destino 'netscanner') '__init__.py'
    if (Test-Path -LiteralPath $init) {
        $m = Select-String -LiteralPath $init -Pattern '__version__\s*=\s*"([^"]+)"' | Select-Object -First 1
        if ($m) { $version = ' (version ' + $m.Matches[0].Groups[1].Value + ')' }
    }
    Decir ('Listo: NetScanner' + $version + ' quedo en ' + $Destino) 'Green'
    Decir 'Se conservaron tu entorno (.venv) y tus resultados.'

    # 7) Arrancar
    if (-not $NoIniciar) {
        Decir 'Arrancando NetScanner (la primera vez instala las librerias: puede tardar uno o dos minutos)...'
        Set-Location -LiteralPath $Destino
        if ($esWindows) { & cmd.exe /c iniciar.bat } else { & bash ./iniciar.sh }
    }
}
catch {
    Write-Host ''
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host 'No se cambio nada de tu instalacion anterior.' -ForegroundColor Yellow
    exit 1
}
finally {
    if ($tmp -and (Test-Path -LiteralPath $tmp)) {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
