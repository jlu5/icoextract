#include <windows.h>

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow) {
    MessageBoxW(NULL, L"Hello world!", L"Test Application", MB_ICONASTERISK);
    return 0;
}
