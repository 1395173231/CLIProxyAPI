@echo off
setlocal enabledelayedexpansion

:: =========================================
:: Config —— 按需修改
:: =========================================
set "IMAGE_NAME=cli-proxy-api"
set "REGISTRY1=ahhhliu"

:: 多平台
set "PLATFORMS=linux/amd64"

:: 构建缓存目录（本地）
set "CACHE_DIR=.docker-cache"

:: 如果要关闭 SBOM/溯源可启用下两行（部分私有仓库更快）
:: set "PROVENANCE=--provenance=false"
:: set "ATTESTATION=--attest=type=provenance,mode=max"

:: =========================================
:: 版本号解析优先级：
:: 1) 命令行参数：publish.bat 1.2.3
:: 2) Git 最新 tag：git describe --tags --abbrev=0
:: 3) 时间戳：YYYYMMDD.HHMM
:: =========================================
set "VERSION_ARG=%~1"
if not "%VERSION_ARG%"=="" (
  set "VERSION=%VERSION_ARG%"
  goto :version_ok
)

:: 尝试从 git tag 获取
:: for /f "usebackq tokens=* delims=" %%i in (`git describe --tags --abbrev^=0 2^>NUL`) do set "VERSION=%%i"
:: if not "%VERSION%"=="" goto :version_ok

:: 用时间戳兜底
call :gen_ts TS
set "VERSION=%TS%"

:version_ok
echo.
echo =^> Using VERSION: %VERSION%
echo.

:: =========================================
:: 预检查：buildx builder
:: =========================================
for /f "tokens=1" %%b in ('docker buildx ls ^| findstr /i /c:"*"') do set "ACTIVE_BUILDER=%%b"
if "%ACTIVE_BUILDER%"=="" (
  echo [i] 未检测到活动 buildx builder，正在创建...
  docker buildx create --use --name chat2api-builder 1>NUL
  if errorlevel 1 (
    echo [!] 创建 buildx builder 失败，请手工检查 docker buildx 环境。
    exit /b 1
  )
)

:: =========================================
:: 可选：登录两个仓库（若已登陆可跳过）
:: =========================================
echo.
echo 如需登录仓库请执行（可跳过）：
echo   docker login %REGISTRY1%
echo.

:: =========================================
:: 统一构建与推送
:: 说明：一次 buildx 带多 -t，会把同一镜像同时推到两个仓库（各含 latest 与版本标签）
:: =========================================
set "TAG1_LATEST=%REGISTRY1%/%IMAGE_NAME%:latest"
set "TAG1_VERSION=%REGISTRY1%/%IMAGE_NAME%:%VERSION%"

echo =^> Build & Push:
echo     %TAG1_LATEST%
echo     %TAG1_VERSION%
echo.

docker buildx build ^
  --platform %PLATFORMS% ^
  --cache-from=type=local,src=%CACHE_DIR% ^
  --cache-to=type=local,dest=%CACHE_DIR%,mode=max ^
  -t %TAG1_LATEST% ^
  -t %TAG1_VERSION% ^
  --push ^
  .
if errorlevel 1 (
  echo [!] 构建或推送失败。
  exit /b 1
)

echo.
echo [OK] 推送完成：
echo   %TAG1_LATEST%
echo   %TAG1_VERSION%
echo   %TAG2_LATEST%
echo   %TAG2_VERSION%
echo.
exit /b 0

:gen_ts
for /f "tokens=2 delims==." %%i in ('wmic os get localdatetime /value 2^>NUL') do set ldt=%%i
set "YYYY=%ldt:~0,4%"
set "MM=%ldt:~4,2%"
set "DD=%ldt:~6,2%"
set "hh=%ldt:~8,2%"
set "nn=%ldt:~10,2%"
set "RAND=%random%"
set "RAND4=%RAND:~-4%"
set "TS=%YYYY%%MM%%DD%.%hh%%nn%-%RAND4%"
endlocal & set "%~1=%TS%"
exit /b 0

