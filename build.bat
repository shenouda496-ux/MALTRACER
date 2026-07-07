@echo off
REM ===========================================================================
REM  build.bat — regenerate the MalTracer Windows distribution (one-dir).
REM  Output:  dist\MalTracer\MalTracer.exe  (+ dependency folder)
REM ===========================================================================
setlocal

echo === MalTracer build ===
echo.

echo [1/3] Installing dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 goto :error

echo.
echo [2/3] Running PyInstaller (one-dir)...
python -m PyInstaller MalTracer.spec --noconfirm --clean
if errorlevel 1 goto :error

echo.
echo [3/3] Smoke-testing the built executable...
"dist\MalTracer\MalTracer.exe" --selftest
if errorlevel 1 goto :error

echo.
echo ===========================================================================
echo  Build complete:  dist\MalTracer\MalTracer.exe
echo  Ship the entire  dist\MalTracer\  folder (zip it for distribution).
echo ===========================================================================
echo.
echo  OPTIONAL — code signing (needs a purchased Authenticode certificate;
echo  unsigned builds trip SmartScreen / AV on other machines — see CHANGES.md):
echo.
echo    signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 ^
echo        "dist\MalTracer\MalTracer.exe"
echo.
goto :eof

:error
echo.
echo *** BUILD FAILED ***
exit /b 1
