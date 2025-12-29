#pragma once

#ifndef WINDOW_POSITION_MANAGER_H
#define WINDOW_POSITION_MANAGER_H

#include <Windows.h>
#include <string>

class WindowPositionManager
{
public:
    // ウィンドウ位置を保存する
    static void SavePosition(HWND hWnd, const std::wstring& registryPath);
    
    // ウィンドウ位置を読み込む
    static void LoadPosition(HWND hWnd, const std::wstring& registryPath);

private:
    // ウィンドウ位置が有効かどうかをチェックする
    static bool IsPositionValid(int x, int y, int width, int height);
};

#endif // WINDOW_POSITION_MANAGER_H