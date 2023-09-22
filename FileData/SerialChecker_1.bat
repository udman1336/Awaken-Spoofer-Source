@echo off
mode con: cols=80 lines=43
:check
title HWID Checker
cls
echo [96mBIOS[97m
echo [90m------------[97m
wmic bios get serialnumber
echo [96mSMBIOS[97m
echo [90m------------[97m
wmic csproduct get uuid
echo [96mBASEBOARD[97m
echo [90m------------[97m
wmic baseboard get serialnumber
echo [96mCPU[97m
echo [90m------------[97m
wmic cpu get serialnumber
echo [96mCHASSIS[97m
echo [90m------------[97m
wmic systemenclosure get serialnumber
echo [96mDISKDRIVE[97m
echo [90m------------[97m
wmic diskdrive get serialnumber
echo [90m------------[97m
echo [96mRAM[97m
wmic memorychip get serialnumber
echo [96mMAC[97m
echo [90m------------[97m
wmic path Win32_NetworkAdapter where "PNPDeviceID like '%%PCI%%' AND NetConnectionStatus=2 AND AdapterTypeID='0'" get MacAddress
echo [92mPress ENTER to see volumeid serial[97m
pause >nul
cls
echo [96mVOLUMEID (C:)[97m
echo [90m------------[97m
vol id c:
echo.
echo [96mVOLUMEID (D:)[97m
echo [90m------------[97m
vol id d:
echo.
echo [96mVOLUMEID (E:)[97m
echo [90m------------[97m
vol id e:
echo.
echo [96mVOLUMEID (F:)[97m
echo [90m------------[97m
vol id f:
echo.
echo [92mPress ENTER to check serial again[97m
pause >nul
goto check