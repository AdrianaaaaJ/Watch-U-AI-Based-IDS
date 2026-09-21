@echo off
setlocal
set "WATCHU_DB=%~dp0watchu.sqlite"
set "HEIDISQL=%~dp0..\..\..\bin\heidisql\heidisql.exe"

if not exist "%WATCHU_DB%" (
    echo Watch-U database not found: %WATCHU_DB%
    echo Open Laragon Terminal and run: php database\init.php
    pause
    exit /b 1
)

if not exist "%HEIDISQL%" (
    where heidisql.exe >nul 2>nul
    if errorlevel 1 (
        echo HeidiSQL was not found in Laragon or PATH.
        echo Create a SQLite session manually and choose: %WATCHU_DB%
        pause
        exit /b 1
    )
    set "HEIDISQL=heidisql.exe"
)

start "Watch-U SQLite" "%HEIDISQL%" -n=10 -l="sqlite3.dll" -h="%WATCHU_DB%"

