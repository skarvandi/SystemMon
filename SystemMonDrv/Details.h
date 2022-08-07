#pragma once

#define POOLTAG 0x41525357 // [A]nti-[R]an[S]om[W]are

typedef struct _ANTI_RANSOMWARE_FILE_TRACE
{
    PEPROCESS  ProcessStruct;
    HANDLE     ProcId;
    LIST_ENTRY FileTraceList;
    UINT32     CountOfModificationsToSensitiveFiles;
    BOOLEAN    IsWhitelisted;
} ANTI_RANSOMWARE_FILE_TRACE, *PANTI_RANSOMWARE_FILE_TRACE;
