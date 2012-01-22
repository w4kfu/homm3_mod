/* This program is just for fun and lulz
	it try to add mofication to heroes of
	might and magic 3 Complete Edition */

#include "common.h"

void	error(char *func_name)
{
	printf("[-] %s() failed, LastError = %x\n", func_name, GetLastError());
	exit(EXIT_FAILURE);
}

int			change_sleep_to_dig(PROCESS_INFORMATION *pi, DWORD ImageBase)
{
	/* Action for button */
	char	buf_action[] =	"\x8B\xCE"				/*	MOV ECX, ESI			*/
							"\x6A\xFF"				/*	PUSH -1					*/
							"\x6A\xFF"				/*	PUSH -1					*/
							"\x6A\xFF"				/*	PUSH -1					*/
							"\x68\x48\xA0\x40\x00"	/*	PUSH 0x0040A048			*/
							"\xE9\x64\x51\x00\x00";	/* JMP 0x0040EC90 (Dig)		*/

	/* Text Show */
	char	buf_text[] =	"\xA1\x48\x65\x6A\x00"			/*	MOV EAX,DWORD PTR DS:[6A6548]	*/
							"\x87\x05\x08\x57\x6A\x00"		/*	XCHG DWORD PTR DS:[6A5708],EAX	*/
							"\xA1\x4C\x65\x6A\x00"			/*	MOV EAX,DWORD PTR DS:[6A654C]	*/
							"\x87\x05\x0C\x57\x6A\x00"		/*	XCHG DWORD PTR DS:[6A570C],EAX	*/
							"\xC3";							/*	RET								*/
	char	buf_jmp[]	=	"\xE9";
	SIZE_T	written = 0;
	DWORD	oldprot;
	DWORD	Addr;

	VirtualProtect((LPVOID)(0x00409B1A), 18, PAGE_EXECUTE_READWRITE, &oldprot);
	if (!WriteProcessMemory(pi->hProcess, (LPVOID)(0x00409B1A), buf_action, 18, &written) || written != 18)
		error("WriteProcessMemory");
	VirtualProtect((LPVOID)(0x00409B1A), 18, oldprot, &oldprot);

	Addr = (DWORD)VirtualAllocEx(pi->hProcess, 0, 23, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!Addr)
		error("VirtualAllocEx");
	if (!WriteProcessMemory(pi->hProcess, (LPVOID)Addr, buf_text, 23, &written) || written != 23)
		error("WriteProcessMemory");

	VirtualProtect((LPVOID)(0x005B9CB4), 5, PAGE_EXECUTE_READWRITE, &oldprot);
	if (!WriteProcessMemory(pi->hProcess, (LPVOID)(0x005B9CB4), buf_jmp, 1, &written) || written != 1)
		error("WriteProcessMemory");
	Addr = Addr - 0x005B9CB4 - 5;
	if (!WriteProcessMemory(pi->hProcess, (LPVOID)(0x005B9CB4 + 1), &Addr, 4, &written) || written != 4)
		error("WriteProcessMemory");
	VirtualProtect((LPVOID)(0x005B9CB4), 5, oldprot, &oldprot);
}

int			setup_nocd(PROCESS_INFORMATION *pi, DWORD ImageBase)
{
	char	buf[5];
	SIZE_T	written = 0;
	DWORD	oldprot;

	/* NOP */
	memset(buf, 0x90, 5);
	VirtualProtect((LPVOID)(ImageBase + 0x10c2f4), 5, PAGE_EXECUTE_READWRITE, &oldprot);
	if (!WriteProcessMemory(pi->hProcess, (LPVOID)(ImageBase + 0x10c2f4), buf, 5, &written) || written != 5)
		error("WriteProcessMemory");
	VirtualProtect((LPVOID)(ImageBase + 0x10c2f4), 5, oldprot, &oldprot);

	/* SETUP JMP */
	buf[0] = 0xEB;
	VirtualProtect((LPVOID)(ImageBase + 0xed9df), 1, PAGE_EXECUTE_READWRITE, &oldprot);
	if (!WriteProcessMemory(pi->hProcess, (LPVOID)(ImageBase + 0xed9df), buf, 1, &written) || written != 1)
		error("WriteProcessMemory");
	VirtualProtect((LPVOID)(ImageBase + 0xed9df), 1, oldprot, &oldprot);

	VirtualProtect((LPVOID)(ImageBase + 0x10bd66), 1, PAGE_EXECUTE_READWRITE, &oldprot);
	if (!WriteProcessMemory(pi->hProcess, (LPVOID)(ImageBase + 0x10bd66), buf, 1, &written) || written != 1)
		error("WriteProcessMemory");
	VirtualProtect((LPVOID)(ImageBase + 0x10bd66), 1, oldprot, &oldprot);
	
	/* If RegKey CdDrive is not set */
	buf[0] = 'D';
	buf[1] = ':';
	buf[2] = 0;
	VirtualProtect((LPVOID)(ImageBase + 0x298838), 1, PAGE_EXECUTE_READWRITE, &oldprot);
	if (!WriteProcessMemory(pi->hProcess, (LPVOID)(ImageBase + 0x298838), buf, 3, &written) || written != 3)
		error("WriteProcessMemory");
	VirtualProtect((LPVOID)(ImageBase + 0x298838), 1, oldprot, &oldprot);

	

	return (0);
}

int		launch_heroes3(void)
{
	STARTUPINFO					si;
	PROCESS_INFORMATION			pi;
	char						path_lsass[260];
	PROCESS_BASIC_INFORMATION	pbi;
	DWORD						ImageBase;
	DWORD						read;

	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));
	if (!CreateProcess(L"HEROES3.EXE", NULL, NULL, NULL, NULL,
					CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW,
					NULL, NULL, &si, &pi))
		error("CreateProcess");
	if (ZwQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) != 0)
		error("ZwQueryInformationProcess");
	if (!ReadProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + 8, &ImageBase, 4, &read) && read != 4)
		error("ReadProcessMemory");
	setup_nocd(&pi, ImageBase);
	change_sleep_to_dig(&pi, ImageBase);
	ResumeThread(pi.hThread);
	return (0);
}

int			main(int argc, char **argv)
{
	FILE	*fp;


	fp = fopen("HEROES3.EXE", "rb");
	if (fp == NULL)
	{
		MessageBoxA(NULL, "Can't find HEROES3.EXE", "Error", MB_ICONERROR);
		return (-1);
	}
	else
	{
		ZwQueryInformationProcess = (long (__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll"),"ZwQueryInformationProcess");
		if (!ZwQueryInformationProcess)
			error("GetProcAddress");
		launch_heroes3();
	}

	return (0);
}