@echo off
color 0F
echo.
echo ============================================================
echo   XANTHOROX-OFCRYPT  AUTOMATED TEST SUITE
echo   Testing ALL encryption methods A-Z
echo ============================================================
echo.

:: Copy calc.exe as test payload
if not exist "test_payload.exe" (
    echo [SETUP] Copying calc.exe as test payload...
    copy "C:\Windows\System32\calc.exe" "test_payload.exe" >nul 2>&1
    if errorlevel 1 (
        echo [SETUP] calc.exe not found, creating synthetic test PE...
        echo MZ > test_payload.exe
    )
)

:: Verify builder DLL exists
if not exist "..\Bin\Builder\XanthoroxCrypted.dll" (
    echo [ERROR] Builder DLL not found at ..\Bin\Builder\XanthoroxCrypted.dll
    echo [ERROR] Run build.bat first to compile the builder.
    pause
    exit /b 1
)

:: Verify stub exists (for patching tests)
if not exist "..\Bin\Stub\Stub.exe" (
    echo [WARN] Stub.exe not found — stub patching tests will be skipped.
)

echo [RUN] Compiling and running test harness...
echo.
dotnet run --project . -- "%cd%\test_payload.exe" "%cd%\..\Bin\Stub\Stub.exe"

echo.
echo ============================================================
echo   TEST RUN COMPLETE
echo ============================================================
pause
