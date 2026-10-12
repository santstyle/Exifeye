@echo off
title ExifEye Installer
setlocal EnableExtensions
cd /d "%~dp0"

echo.
echo  ============================================
echo   ExifEye - Image Intelligence - Installer
echo  ============================================
echo.

echo  [1/3] Installing Python dependencies...
py -m pip install -r requirements.txt --quiet --disable-pip-version-check
if errorlevel 1 (
    echo.
    echo  [ERROR] Gagal menginstall dependencies. Cek Python/pip.
    pause
    exit /b 1
)

echo  [2/3] Registering 'exifeye' as a global command...
py -m pip install -e . --quiet --disable-pip-version-check --no-warn-script-location
if errorlevel 1 (
    echo.
    echo  [ERROR] Gagal mendaftarkan command exifeye.
    pause
    exit /b 1
)

echo  [3/3] Adding command to PATH (otomatis, sekali saja)...
for /f "usebackq delims=" %%I in (`py -c "import sysconfig; print(sysconfig.get_path('scripts'))"`) do set "SCRIPTS_DIR=%%I"

:: NOTE: single-quoted PowerShell strings keep backslashes literal, so
:: SCRIPTS_DIR must NOT be escaped here.
"%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "$s='%SCRIPTS_DIR%'; $p=[Environment]::GetEnvironmentVariable('Path','User'); if(-not $p){$p=''}; if($p -notlike ('*'+$s+'*')){ [Environment]::SetEnvironmentVariable('Path', ($p.TrimEnd(';')+';'+$s), 'User'); Write-Output 'PATH_UPDATED' } else { Write-Output 'PATH_OK' }"

echo.
echo  ============================================
echo   Selesai! Sekarang ketik:  exifeye
echo   (atau double-click start.bat di folder ini)
echo   Termux/PowerShell yang sudah terbuka perlu
echo   ditutup-dibuka dulu supaya PATH-nya kebaca.
echo  ============================================
echo.
pause