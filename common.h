#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#if !defined NTSTATUS
typedef LONG NTSTATUS;
#endif

#define STATUS_SUCCESS 0

#if !defined PROCESSINFOCLASS
typedef LONG PROCESSINFOCLASS;
#endif

#if !defined PPEB
typedef struct _PEB *PPEB;
#endif

#if !defined PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
#endif;

NTSTATUS (__stdcall *ZwQueryInformationProcess)(
  HANDLE  ProcessHandle,
  PROCESSINFOCLASS  ProcessInformationClass,
  PVOID  ProcessInformation,
  ULONG  ProcessInformationLength,
  PULONG  ReturnLength  OPTIONAL
  );