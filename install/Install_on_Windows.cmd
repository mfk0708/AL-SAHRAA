@echo off
rem Double-click to install Contract Assessment Tools on this Windows server (asks for administrator rights).
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"%~dp0install_windows.ps1\"'"
