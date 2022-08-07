#pragma once

#pragma prefast(disable \
                : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

#define PTDBG_TRACE_ROUTINES         0x00000001
#define PTDBG_TRACE_OPERATION_STATUS 0x00000002

//
// 1 << 21 (2 MB)
//
#define MAXIMUM_SIZE_OF_FILE_TO_BACKUP 2097152

#define MAX_PATH 1000

#define DRIVER_CONTEXT_TAG 'xcbF'
#define DRIVER_TAG         'bF'

struct FileContext
{
    Mutex          Lock;
    UNICODE_STRING FileName;
    BOOLEAN        Written;
};

NTSTATUS
BackupFile(PUNICODE_STRING FileName, PCFLT_RELATED_OBJECTS FltObjects, BOOLEAN FromDeleteRoutines, PUNICODE_STRING PathInTheCaseOfDeletion);
bool
IsProtectedBackupFile(PCUNICODE_STRING directory);

bool
IsUserDirectory(PCUNICODE_STRING directory, PBOOLEAN ImmediateAction);

/*************************************************************************
	Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath);

NTSTATUS
SystemMonInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE              VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE      VolumeFilesystemType);

VOID
SystemMonInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS       FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID
SystemMonInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS       FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

NTSTATUS
SystemMonUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS
SystemMonInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS             FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
SystemMonPreWrite(
    _Inout_ PFLT_CALLBACK_DATA     Data,
    _In_ PCFLT_RELATED_OBJECTS     FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID * CompletionContext);

FLT_POSTOP_CALLBACK_STATUS
SystemMonPostCreate(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_opt_ PVOID                CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS
SystemMonPostCleanup(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_opt_ PVOID                CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

NTSTATUS
PortConnectNotify(
    _In_ PFLT_PORT                            ClientPort,
    _In_opt_ PVOID                            ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG                                SizeOfContext,
    _Outptr_result_maybenull_ PVOID * ConnectionPortCookie);

void
PortDisconnectNotify(_In_opt_ PVOID ConnectionCookie);

NTSTATUS
PortMessageNotify(
    _In_opt_ PVOID                                                                 PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID                                  InputBuffer,
    _In_ ULONG                                                                     InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG                                                                     OutputBufferLength,
    _Out_ PULONG                                                                   ReturnOutputBufferLength);

FLT_PREOP_CALLBACK_STATUS
DelProtectPreCreate(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects, PVOID *);

FLT_PREOP_CALLBACK_STATUS
DelProtectPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA     Data,
    _In_ PCFLT_RELATED_OBJECTS     FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID * CompletionContext);

NTSTATUS
CopyFile(PUNICODE_STRING SourceFile, PUNICODE_STRING DestinationFile);

EXTERN_C_END

BOOLEAN
AddAndCheckSuspectOperation(OPERATION_TYPE Operation, PBOOLEAN IsProcessWhiteListed);

//
//  Assign text sections for each routine.
//
#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, DriverEntry)
#    pragma alloc_text(PAGE, SystemMonUnload)
#    pragma alloc_text(PAGE, SystemMonInstanceQueryTeardown)
#    pragma alloc_text(PAGE, SystemMonInstanceSetup)
#    pragma alloc_text(PAGE, SystemMonInstanceTeardownStart)
#    pragma alloc_text(PAGE, SystemMonInstanceTeardownComplete)
#endif

NTSTATUS
BackupFile(PUNICODE_STRING FileName, PCFLT_RELATED_OBJECTS FltObjects, BOOLEAN FromDeleteRoutines, PUNICODE_STRING PathInTheCaseOfDeletion);

BOOLEAN
IsFileExists(PUNICODE_STRING dirName);

VOID
AppendPostFixAndCheckIfFileExists(PUNICODE_STRING targetFileName);

bool
IsDeleteAllowed(_In_ PFLT_CALLBACK_DATA Data, OPERATION_TYPE Operation, PCFLT_RELATED_OBJECTS FltObjects);
