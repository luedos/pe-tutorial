#include <iostream>
#include <Windows.h>

//Несколько TLS-переменных
__declspec(thread) int a = 123;
__declspec(thread) int b = 456;
__declspec(thread) char c[128];



//Процедура потока (пустая, просто, чтобы коллбэки вызвались)
DWORD __stdcall thread(void*)
{
	ExitThread(0);
}

VOID WINAPI tls_callback1(
	PVOID DllHandle,
	DWORD Reason,
	PVOID Reserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
		MessageBoxA(0, "Process Callback!", "Process Callback!", 0);
	else if (Reason == DLL_THREAD_ATTACH)
		MessageBoxA(0, "Thread Callback!", "Thread Callback!", 0);
}
VOID WINAPI tls_callback2(
	PVOID DllHandle,
	DWORD Reason,
	PVOID Reserved)
{
	if (Reason == DLL_PROCESS_ATTACH)
		MessageBoxA(0, "Process Callback 2!", "Process Callback 2!", 0);
	else if (Reason == DLL_THREAD_ATTACH)
		MessageBoxA(0, "Thread Callback 2!", "Thread Callback 2!", 0);
}
//-------------------------------------------------------------------------
// TLS 32/64 bits example by Elias Bachaalany <lallousz-x86@yahoo.com>
#ifdef _M_AMD64
	#pragma comment (linker, "/INCLUDE:_tls_used")
	#pragma comment (linker, "/INCLUDE:p_tls_callback1")
	#pragma const_seg(push)
	#pragma const_seg(".CRT$XLAAA")
		EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback1 = tls_callback1;
	#pragma const_seg(".CRT$XLAAB")
		EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback2 = tls_callback2;
	#pragma const_seg(pop)
#endif
#ifdef _M_IX86
	#pragma comment (linker, "/INCLUDE:__tls_used")
	#pragma comment (linker, "/INCLUDE:_p_tls_callback1")
	#pragma data_seg(push)
	#pragma data_seg(".CRT$XLAAA")
		EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback1 = tls_callback1;
	#pragma data_seg(".CRT$XLAAB")
		EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback2 = tls_callback2;
	#pragma data_seg(pop)
#endif

int main()
{
	//Выводим переменные из TLS
	std::cout << "Relocation test " << a << ", " << b << std::endl;
	c[126] = 'x';
	c[127] = 0;
	std::cout << &c[126] << std::endl;

	//Спим 2 секунды
	Sleep(2000);

	//Запускаем поток и сразу закрываем его хендл
	CloseHandle(CreateThread(0, 0, &thread, 0, 0, 0));

	//Спим 2 секунды
	Sleep(2000);

	std::cout << "---end---" << std::endl;
	return 0;
}