@echo off
title ExifEye - Image Intelligence
cd /d "%~dp0"
where exifeye >nul 2>nul
if %errorlevel%==0 (
    exifeye %*
) else (
    py exifeye.py %*
)
if errorlevel 1 pause