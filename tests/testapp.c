#include <windows.h>

#ifdef __WATCOMC__
/* Windows 3.x (Win16) */
int PASCAL WinMain(HANDLE hInstance, HANDLE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
#else
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, int nCmdShow)
#endif
{
    MessageBox(NULL, "Hello world!", "Test Application", MB_ICONASTERISK);
    return 0;
}
