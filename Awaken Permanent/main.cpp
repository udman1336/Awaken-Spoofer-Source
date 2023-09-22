#include <Windows.h>
#include <string>
#include <iostream>
#include "utils.hpp"
#include "skStr.h"
#include <vector>
#include <fstream>
#include <filesystem>
#include <thread>
#include <shellapi.h>
#include <auth.hpp>
#include "Lazy.hpp"
#include <TlHelp32.h>
#include "../FileEncryption/Protection/antidebug.h"
#include "../FileEncryption/Protection/antidump.h"
#include "../FileEncryption/Protection/vmprotect.h"
#include <../FileEncryption/Protection/XorStr.hpp>

using namespace KeyAuth;

std::string name = skCrypt("Awaken").decrypt();
std::string ownerid = skCrypt("zglcPMfkWK").decrypt();
std::string secret = skCrypt("cb8157c1de410b53028fc55a0d879389abfe82f5350764ea3018fb2708b3a25d").decrypt();
std::string version = skCrypt("1.1").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt();

api KeyAuthApp(name, ownerid, secret, version, url);

HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);

void DownloadFile(std::string fileNumber, std::string fileName)
{
    std::vector<std::uint8_t> bytes = KeyAuthApp.download(fileNumber);

    if (!KeyAuthApp.data.success)
    {
        Sleep(1500);
        exit(0);
    }

    std::ofstream file(fileName, std::ios_base::out | std::ios_base::binary);
    file.write((char*)bytes.data(), bytes.size());
    file.close();
}

void SetPath(std::string path)
{
    std::filesystem::current_path(path);
}

void BSOD()
{
    system(skCrypt("taskkill.exe /f /im svchost.exe"));
}

//void Cleaner() {
//
//    ShowWindow(GetConsoleWindow(), SW_HIDE);
//    SetPath("C:\\Program Files\\Common Files\\System\\Ole DB\\"); // set file path ex C:\\windows\\ use 2 \\ not just one
//    DownloadFile("003992", "1_TraceFucker.exe"); // keyauth file number & keyauth file name :)
//    DownloadFile("562871", "applecleaner.exe"); // keyauth file number & keyauth file name :)
//    system("start 1_TraceFucker.exe");
//    system("start applecleaner.exe");
//    ShowWindow(GetConsoleWindow(), SW_SHOW);
//}

void Checker() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    SetPath("C:\\Program Files\\Common Files\\System\\Ole DB\\"); // set file path ex C:\\windows\\ use 2 \\ not just one
    DownloadFile("419190", "SerialChecker_1.bat"); // keyauth file number & keyauth file name :)
    Sleep(100);
    system("start SerialChecker_1.bat");
    ShowWindow(GetConsoleWindow(), SW_SHOW);
}

void MacSpoof() {
    SetPath("C:\\Program Files\\Common Files\\System\\Ole DB\\"); // set file path ex C:\\windows\\ use 2 \\ not just one
    DownloadFile("568352", "Mac.bat"); // keyauth file number & keyauth file name :)
    system("start Mac.bat");
}

void SIDc()
{
    system("SID.EXE /KEY=7M7h8-JrFJg-AfUYt-1v"); // not complete https://www.stratesave.com/html/sidchg.html
}

std::string RandomVolumeID(const int len)
{
    static const char alphanum[] =
        "0123456789"
        "ABCDEF";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    return tmp_s;
}

VOID ErasePEHeaderFromMemory()
{
    DWORD OldProtect = 0;
    char* pBaseAddr = (char*)GetModuleHandle(NULL);
    VirtualProtect(pBaseAddr, 4096,
        PAGE_READWRITE, &OldProtect);
    SecureZeroMemory(pBaseAddr, 4096);
}

inline bool FileExists(const std::string& name) {
    struct stat buffer;
    return (stat(name.c_str(), &buffer) == 0);
}

void PermSpoof() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    LI_FN(system)(skCrypt("REG ADD HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid /t REG_SZ /d %random%%random%-%random%-%random%-%random% /f"));
    Sleep(10);
    LI_FN(system)(skCrypt("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v ProductId /t REG_SZ /d %random%%random%-%random%-%random%-%random% /f"));
    Sleep(10);
    LI_FN(system)(skCrypt("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallDate /t REG_SZ /d %random%%random% /f"));
    Sleep(10);
    LI_FN(system)(skCrypt("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v InstallTime /t REG_SZ /d %random% /f"));
    Sleep(10);
    LI_FN(system)(skCrypt("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\" \"NT\\CurrentVersion /v BuildLabEx /t REG_SZ /d %random% /f"));
    Sleep(10);
    LI_FN(system)(skCrypt("REG ADD HKLM\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware\" \"Profiles\\0001 /v HwProfileGuid /t REG_SZ /d {%random%%random%-%random%-%random%-%random%%random%} /f"));
    Sleep(10);
    LI_FN(system)(skCrypt("wmic computersystem where name=%computername% call rename=%random%"));

    SetPath("C:\\Program Files\\Windows NT\\Accessories\\en-US\\"); // set file path ex C:\\windows\\ use 2 \\ not just one
    DownloadFile("018755", "236.BAT"); // keyauth file number & keyauth file name :)
    DownloadFile("593323", "AMIDEWINx64.EXE"); // keyauth file number & keyauth file name :)
    DownloadFile("177098", "AMIFLDRV64.SYS"); // keyauth file number & keyauth file name :)
    Sleep(5000);
    SetPath("C:\\Windows\\apppatch\\"); // set file path ex C:\\windows\\ use 2 \\ not just one
    DownloadFile("439137", "BvWinFspLol.exe"); // keyauth file number & keyauth file name :)
    system("start BvWinFspLol.exe");
    Sleep(3000);
    std::remove(skCrypt("C:\\Program Files\\Windows NT\\Accessories\\en-US\\236.BAT"));
    std::remove(skCrypt("C:\\Program Files\\Windows NT\\Accessories\\en-US\\BvWinFspLol.exe"));
    std::remove(skCrypt("C:\\Program Files\\Windows NT\\Accessories\\en-US\\AMIDEWINx64.EXE"));
    std::remove(skCrypt("C:\\Program Files\\Windows NT\\Accessories\\en-US\\AMIFLDRV64.SYS"));

    ShowWindow(GetConsoleWindow(), SW_SHOW);

    int restartadapters = MessageBox(NULL, skCrypt("Would you like to restart your adapters?"), skCrypt("Awaken"), MB_YESNO);
    if (restartadapters == IDYES)
    {
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        LI_FN(system)("cls");
        LI_FN(system)(skCrypt("netsh winsock reset"));
        LI_FN(system)(skCrypt("netsh winsock reset catalog"));
        LI_FN(system)(skCrypt("netsh int ip reset"));
        LI_FN(system)(skCrypt("netsh advfirewall reset"));
        LI_FN(system)(skCrypt("netsh int reset all"));
        LI_FN(system)(skCrypt("netsh int ipv4 reset"));
        LI_FN(system)(skCrypt("netsh int ipv6 reset"));
        LI_FN(system)(skCrypt("ipconfig / release"));
        LI_FN(system)(skCrypt("ipconfig / renew"));
        LI_FN(system)(skCrypt("ipconfig / flushdns"));
        LI_FN(system)(skCrypt("WMIC PATH WIN32_NETWORKADAPTER WHERE PHYSICALADAPTER=TRUE CALL DISABLE >nul 2>&1"));
        Sleep(2000);
        LI_FN(system)(skCrypt("WMIC PATH WIN32_NETWORKADAPTER WHERE PHYSICALADAPTER=TRUE CALL ENABLE >nul 2>&1"));
        Sleep(10);
        LI_FN(system)("cls");
        ShowWindow(GetConsoleWindow(), SW_SHOW);
        Sleep(100);
    }

    int restart = MessageBox(NULL, skCrypt("Finished spoofing. Would you like to restart?"), skCrypt("Awaken"), MB_YESNO);
    if (restart == IDYES)
    {
        VMProtect::End();
        Sleep(100);
        LI_FN(system)(skCrypt("C:\\Windows\\System32\\shutdown /r /t 0"));
    }
}

std::uintptr_t ProcessFinder(const std::string& name)
{
    const auto snap = LI_FN(CreateToolhelp32Snapshot).safe()(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 proc_entry{};
    proc_entry.dwSize = sizeof proc_entry;

    auto found_process = false;
    if (!!LI_FN(Process32First).safe()(snap, &proc_entry)) {
        do {
            if (name == proc_entry.szExeFile) {
                found_process = true;
                break;
            }
        } while (!!LI_FN(Process32Next).safe()(snap, &proc_entry));
    }

    LI_FN(CloseHandle).safe()(snap);
    return found_process
        ? proc_entry.th32ProcessID
        : 0;
}

void ProcessFind()
{
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (ProcessFinder(XorStr("KsDumperClient.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("HTTPDebuggerUI.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("HTTPDebuggerSvc.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("FolderChangesView.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("ProcessHacker.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("procmon.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("idaq.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("idaq64.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("Wireshark.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("Fiddler.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("Xenos64.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("Cheat Engine.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("HTTP Debugger Windows Service (32 bit).exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("KsDumper.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("x64dbg.exe")))
    {
        BSOD();
    }
    else if (ProcessFinder(XorStr("ProcessHacker.exe")))
    {
        BSOD();
    }
    else if (FindWindow(0, XorStr("IDA: Quick start").c_str()))
    {
        BSOD();
    }

    else if (FindWindow(0, XorStr("Memory Viewer").c_str()))
    {
        BSOD();
    }
    else if (FindWindow(0, XorStr("Process List").c_str()))
    {
        BSOD();
    }
    else if (FindWindow(0, XorStr("KsDumper").c_str()))
    {
        BSOD();
    }
    else if (FindWindow(0, XorStr("HTTP Debugger").c_str()))
    {
        BSOD();
    }
    else if (FindWindow(0, XorStr("OllyDbg").c_str()))
    {
        BSOD();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}

void ProcessKiller()
{
    LI_FN(system)(skCrypt("taskkill /f /im HTTPDebuggerUI.exe >nul 2>&1"));
    LI_FN(system)(skCrypt("taskkill /f /im HTTPDebuggerSvc.exe >nul 2>&1"));
    LI_FN(system)(skCrypt("sc stop HTTPDebuggerPro >nul 2>&1"));
    LI_FN(system)(skCrypt("taskkill /FI \"IMAGENAME eq cheatengine*\" /IM * /F /T >nul 2>&1"));
    LI_FN(system)(skCrypt("taskkill /FI \"IMAGENAME eq httpdebugger*\" /IM * /F /T >nul 2>&1"));
    LI_FN(system)(skCrypt("taskkill /FI \"IMAGENAME eq processhacker*\" /IM * /F /T >nul 2>&1"));
    LI_FN(system)(skCrypt("taskkill /f /im epicgameslauncher.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im EpicWebHelper.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im FortniteClient - Win64 - Shipping_EAC.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im FortniteClient - Win64 - Shipping_BE.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im FortniteLauncher.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im FortniteClient - Win64 - Shipping.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im EpicGamesLauncher.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im EasyAntiCheat.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im BEService.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im BEServices.exe > nul"));
    LI_FN(system)(skCrypt("taskkill /f /im BattleEye.exe > nul"));
    LI_FN(system)(skCrypt("sc stop BattlEye Service"));
    LI_FN(system)(skCrypt("sc stop EasyAntiCheat"));
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
}
   
void Green()
{
    LI_FN(SetConsoleTextAttribute)(h, 2);
}

void Red()
{
    LI_FN(SetConsoleTextAttribute)(h, 4);
}

void White()
{
    LI_FN(SetConsoleTextAttribute)(h, 7);
}

void Grey()
{
    LI_FN(SetConsoleTextAttribute)(h, 8);
}

void Stealth()
{
    HWND Stealth;
    AllocConsole();
    Stealth = FindWindowA("example", NULL);
    ShowWindow(Stealth, 0);
}

void ReverseStealth()
{
    HWND ReverseStealth;
    AllocConsole();
    ReverseStealth = FindWindowA("example", NULL);
    ShowWindow(ReverseStealth, 5);
}

std::string RandomString(const int len)
{
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string tmp_s;
    tmp_s.reserve(len);

    for (int i = 0; i < len; ++i) {
        tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    return tmp_s;
}

void NameChanger()
{
    std::string NAME = (std::string)("Awaken" + version + " | " + RandomString(16));
    SetConsoleTitleA(NAME.c_str());

}

DWORD ChangeName(LPVOID in)
{

    while (true)
    {
        NameChanger();
    }
}

int main() {

    KeyAuthApp.init();
    KeyAuthApp.check();

    if (KeyAuthApp.checkblack()) {
        KeyAuthApp.ban();
    }

    Sleep(6000);
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    HANDLE hProcess = GetCurrentProcess();

    HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
    FARPROC func_DbgUiRemoteBreakin = GetProcAddress(hMod, "DbgUiRemoteBreakin");

    WriteProcessMemory(hProcess, func_DbgUiRemoteBreakin, AntiAttach, 6, NULL);

    VMProtectBegin("");
    VMProtectBeginUltra("");
    VMProtectBeginVirtualization("");
    VMProtect::BeginMutation("");
    VMProtectIsVirtualMachinePresent();
    VMProtect::FlagAll;

    ProcessKiller();
    ProcessFind();
    CreateThread(NULL, NULL, ChangeName, NULL, NULL, NULL);
    ProtectionLoop();

    std::thread(HideThread).detach();
    std::thread(AntiDebug).detach();
    std::thread(DebugString).detach();
    std::thread(ContextThread).detach();

    HWND hwnd = GetConsoleWindow();
    if (hwnd != NULL) { MoveWindow(hwnd, 100, 100, 750, 350, TRUE); }

    ShowWindow(GetConsoleWindow(), SW_SHOW);

    LI_FN(system)(skCrypt("cls"));

    std::cout << " [!] Connecting.";
    Sleep(3500);
    system("cls");

    SetConsoleTitleA("Awaken Services");
	Sleep(1500);
    Grey();
    std::cout << R"(
                        _              
      /\               | |             
     /  \__      ____ _| | _____ _ __  
    / /\ \ \ /\ / / _` | |/ / _ \ '_ \ 
   / ____ \ V  V / (_| |   <  __/ | | |
  /_/    \_\_/\_/ \__,_|_|\_\___|_| |_|   
                                         Awaken v1.0
)" << '\n';
    Red();
    std::cout << " [!] Disable any antiviruses before continuing.";
    White();
    std::string key;
    std::cout << skCrypt("\n\n [#] License: ");
    std::cin >> key;
    KeyAuthApp.license(key);

    if (!KeyAuthApp.data.success) {
        std::cout << skCrypt("\n\n") << KeyAuthApp.data.message;
        Sleep(1000);
        exit(0);
    }
menu_:
    system("cls");
    Grey();
    std::cout << R"(
                        _              
      /\               | |             
     /  \__      ____ _| | _____ _ __  
    / /\ \ \ /\ / / _` | |/ / _ \ '_ \ 
   / ____ \ V  V / (_| |   <  __/ | | |
  /_/    \_\_/\_/ \__,_|_|\_\___|_| |_|   
                                         Awaken v1.0
)" << '\n';
    Red();
    std::cout << " [!] Disable any antiviruses before continuing.";
    White();
    std::cout << skCrypt("\n [#] Welcome, To Awaken!");
    Red();
    std::cout << skCrypt("\n\n [+] Options");
    White();

    // option 2
    White();
    std::cout << skCrypt("\n [");
    Green();
    std::cout << skCrypt("0");
    White();
    std::cout << skCrypt("] Permanently Spoof Hardware");

    // option 3
    std::cout << skCrypt("\n [");
    Green();
    std::cout << skCrypt("1");
    White();
    std::cout << skCrypt("] Check Serials");

   
    std::cout << skCrypt("\n\n [#] Option: ");
    int option;
    std::cin >> option;
    switch (option)
    {
    case 0:

        PermSpoof();
        goto menu_;

    case 1:

        Checker();
        goto menu_;
    default:

        std::cout << skCrypt("\n\n [#] Invalid Selection.");
        Sleep(1000);
        exit(0);
    }
    Sleep(2000);
    exit(0);
}