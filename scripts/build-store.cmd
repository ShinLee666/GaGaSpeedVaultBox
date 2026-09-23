@echo off
REM VaultBox 微软商店版构建脚本
REM 纯本地存储（--no-default-features，不含任何联网代码），NSIS 单安装包，
REM WebView2 使用 offlineInstaller 模式（内嵌运行时，满足商店"安装包必须离线"要求）。
REM 产物：src-tauri\target\release\bundle\nsis\VaultBox_0.1.0_x64-setup.exe
setlocal
cd /d "%~dp0\.."
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
set CI=true
pnpm tauri build --config src-tauri/tauri.microsoftstore.conf.json --bundles nsis -- --no-default-features
if errorlevel 1 (echo 构建失败 & exit /b 1)
echo.
echo 商店版安装包已生成：src-tauri\target\release\bundle\nsis\
endlocal
