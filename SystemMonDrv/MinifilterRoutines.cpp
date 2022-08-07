#include "pch.h"

//
// Global variables included here
//
#include "Globals.h"

PFLT_FILTER gFilterHandle;
ULONG_PTR   OperationStatusCtx = 1;
PFLT_PORT   FilterPort;
PFLT_PORT   SendClientPort;
ULONG       gTraceFlags = 0;

#define PT_DBG_PRINT(_dbgLevel, _string) \
    (FlagOn(gTraceFlags, (_dbgLevel)) ? DbgPrint _string : ((int)0))

template <typename TLock>
struct AutoLock1
{
    AutoLock1(TLock & lock) :
        _lock(lock)
    {
        _lock.Lock();
    }

    ~AutoLock1()
    {
        _lock.Unlock();
    }

private:
    TLock & _lock;
};

template <typename TLock>
struct AutoLock
{
    AutoLock(TLock & lock) :
        _lock(lock)
    {
        _lock.Lock();
    }
    ~AutoLock()
    {
        _lock.Unlock();
    }

private:
    TLock & _lock;
};

void
FileContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE /* ContextType */)
{
    auto fileContext = (FileContext *)Context;
    if (fileContext->FileName.Buffer)
        ExFreePool(fileContext->FileName.Buffer);
}

//
//  operation registration
//
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_CREATE, 0, DelProtectPreCreate, SystemMonPostCreate},
    {IRP_MJ_WRITE, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, SystemMonPreWrite},
    {IRP_MJ_SET_INFORMATION, 0, DelProtectPreSetInformation, nullptr},
    {IRP_MJ_CLEANUP, 0, nullptr, SystemMonPostCleanup},

    {IRP_MJ_OPERATION_END}};

//
//  This defines what we want to filter with FltMgr
//
const FLT_CONTEXT_REGISTRATION Contexts[] = {
    {FLT_FILE_CONTEXT, 0, nullptr, sizeof(FileContext), DRIVER_CONTEXT_TAG},
    {FLT_CONTEXT_END}};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION), //  Size
    FLT_REGISTRATION_VERSION, //  Version
    0,                        //  Flags

    Contexts,  //  Context
    Callbacks, //  Operation callbacks

    SystemMonUnload, //  MiniFilterUnload

    SystemMonInstanceSetup,
    SystemMonInstanceQueryTeardown,
    SystemMonInstanceTeardownStart,
    SystemMonInstanceTeardownComplete,

    nullptr, //  GenerateFileName
    nullptr, //  GenerateDestinationFileName
    nullptr  //  NormalizeNameComponent
};

BOOLEAN
CentralCheck(PUNICODE_STRING path, PCFLT_RELATED_OBJECTS FltObjects, OPERATION_TYPE Operation)
{
    BOOLEAN  ImmAction;
    BOOLEAN  ShouldBeSuspended = FALSE;
    BOOLEAN  IsProcessWhitelisted;
    BOOLEAN  Allow = TRUE;
    NTSTATUS Status;

    //
    // KdPrint(("Checking directory: %wZ\n", &path));
    //
    if (IsUserDirectory(path, &ImmAction))
    {
        if (MmGetPhysicalAddress((PVOID)((INT64)path->Buffer + path->Length)).QuadPart == NULL)
        {
            return Allow;
        }

        //
        // Add operation to suspecious list and check it possible ransomware
        //
        ShouldBeSuspended = AddAndCheckSuspectOperation(Operation, &IsProcessWhitelisted);

        //
        // Check if the process is whitelisted then there is no need to
        // get the backup
        //
        if (!IsProcessWhitelisted)
        {
            if (Operation == OPERATION_DELETE_FILE_ON_CLOSE || Operation == OPERATION_DELETE_FILE_SET_INFORMATION)
            {
                Status = BackupFile(NULL, NULL, TRUE, path);
            }
            else if (Operation == OPERATION_WRITE_FILE)
            {
                Status = BackupFile(path, FltObjects, FALSE, NULL);
            }
            else
            {
                //
                // New operation type detected
                //
                DbgBreakPoint();
            }
        }

        if (ImmAction)
        {
            ShouldBeSuspended = TRUE;
        }

        if (ShouldBeSuspended)
        {
            Allow = FALSE;
        }

        if (SendClientPort)
        {
            USHORT nameLen = path->Length;
            USHORT len     = sizeof(ANTI_RANSOMWARE_PORT_MESSAGE) + nameLen;
            auto   msg     = (PANTI_RANSOMWARE_PORT_MESSAGE)ExAllocatePoolWithTag(PagedPool, len, DRIVER_TAG);
            if (msg)
            {
                RtlZeroMemory(msg, len);
                msg->ImmediateActions  = ImmAction;
                msg->OperationType     = Operation;
                msg->FileNameLength    = nameLen / sizeof(WCHAR);
                msg->ProcessId         = PsGetCurrentProcessId();
                msg->ShouldBeSuspended = ShouldBeSuspended;
                RtlCopyMemory(msg->FileName, path->Buffer, nameLen);
                LARGE_INTEGER timeout;
                timeout.QuadPart = -10000 * 100; // 100msec
                FltSendMessage(gFilterHandle, &SendClientPort, msg, len, nullptr, nullptr, &timeout);
                ExFreePool(msg);
            }
        }
    }

    return Allow;
}

/**
 * @brief This routine is called whenever a new instance is created on a volume. This
 * gives us a chance to decide if we need to attach to this volume or not.
 * @details If this routine is not defined in the registration structure, automatic
 * instances are always created.
 *
 * @param FltObjects Pointer to the FLT_RELATED_OBJECTS data structure containing
 * opaque handles to this filter, instance and its associated volume.
 * @param Flags Flags describing the reason for this attach request.
 * @param VolumeDeviceType
 * @param VolumeFilesystemType
 * @return NTSTATUS STATUS_SUCCESS - attach or STATUS_FLT_DO_NOT_ATTACH - do not attach
 */
NTSTATUS
SystemMonInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE              VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE      VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    PAGED_CODE();

    if (VolumeFilesystemType != FLT_FSTYPE_NTFS)
    {
        DbgPrint("Not attaching to non-NTFS volume\n");
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief This is called when an instance is being manually deleted by a
 *	call to FltDetachVolume or FilterDetach thereby giving us a
 *	chance to fail that detach request.
 * @details If this routine is not defined in the registration structure, explicit
 *	detach requests via FltDetachVolume or FilterDetach will always be
 *	failed.
 *
 * @param FltObjects Pointer to the FLT_RELATED_OBJECTS data structure containing
 * opaque handles to this filter, instance and its associated volume.
 * @param Flags Indicating where this detach request came from.
 * @return NTSTATUS Returns the status of this operation.
 */
NTSTATUS
SystemMonInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS             FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    DbgPrint("SystemMon!SystemMonInstanceQueryTeardown: Entered\n");

    return STATUS_SUCCESS;
}

FLT_PREOP_CALLBACK_STATUS
SystemMonPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID * CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Data);

    if (!g_SystemMonIsEnabled)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // get the file context if exists
    //
    FileContext * context;
    BOOLEAN       ShouldBeSuspended = FALSE;
    BOOLEAN       ImmAction         = FALSE;
    BOOLEAN       IsProcessWhitelisted;

    auto status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status) || context == nullptr)
    {
        //
        // no context, continue normally
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // acquire the fast mutex in case of multiple writes
    //
    AutoLock1<Mutex> locker(context->Lock);

    if (!context->Written)
    {
        status = STATUS_SUCCESS;

        CentralCheck(&context->FileName, FltObjects, OPERATION_WRITE_FILE);

        context->Written = TRUE;
    }

    FltReleaseContext(context);

    if (!ShouldBeSuspended)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    else
    {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }
}

FLT_POSTOP_CALLBACK_STATUS
SystemMonPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    BOOLEAN ImmediateAction = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_SystemMonIsEnabled || Flags & FLTFL_POST_OPERATION_DRAINING)
        return FLT_POSTOP_FINISHED_PROCESSING;

    const auto & params = Data->Iopb->Parameters.Create;
    if (Data->RequestorMode == KernelMode || (params.SecurityContext->DesiredAccess & FILE_WRITE_DATA) == 0 || Data->IoStatus.Information == FILE_DOES_NOT_EXIST)
    {
        //
        // kernel caller, not write access or a new file - skip
        //
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // get file name
    //
    FilterFileNameInformation fileNameInfo(Data);

    if (!fileNameInfo)
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!NT_SUCCESS(fileNameInfo.Parse()))
        return FLT_POSTOP_FINISHED_PROCESSING;

    if (!CentralCheck(&fileNameInfo->Name, FltObjects, OPERATION_WRITE_FILE))
    {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    //
    // if it's not the default stream, we don't care
    //
    if (fileNameInfo->Stream.Length > 0)
        return FLT_POSTOP_FINISHED_PROCESSING;

    //
    // allocate and initialize a file context
    //
    FileContext * context;
    auto          status = FltAllocateContext(FltObjects->Filter, FLT_FILE_CONTEXT, sizeof(FileContext), PagedPool, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("Failed to allocate file context (0x%08X)\n", status));
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    context->Written                = FALSE;
    context->FileName.MaximumLength = fileNameInfo->Name.Length;
    context->FileName.Buffer        = (WCHAR *)ExAllocatePoolWithTag(PagedPool, fileNameInfo->Name.Length, DRIVER_TAG);
    if (!context->FileName.Buffer)
    {
        FltReleaseContext(context);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    RtlCopyUnicodeString(&context->FileName, &fileNameInfo->Name);
    context->Lock.Init();
    status = FltSetFileContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, nullptr);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("Failed to set file context (0x%08X)\n", status));
        ExFreePool(context->FileName.Buffer);
    }
    FltReleaseContext(context);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
SystemMonPostCleanup(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Data);

    FileContext * context;

    auto status = FltGetFileContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT *)&context);
    if (!NT_SUCCESS(status) || context == nullptr)
    {
        //
        // no context, continue normally
        //
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (context->FileName.Buffer)
        ExFreePool(context->FileName.Buffer);
    FltReleaseContext(context);
    FltDeleteContext(context);

    return FLT_POSTOP_FINISHED_PROCESSING;
}

_Use_decl_annotations_
NTSTATUS
PortConnectNotify(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext, PVOID * ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    SendClientPort = ClientPort;

    return STATUS_SUCCESS;
}

void
PortDisconnectNotify(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    FltCloseClientPort(gFilterHandle, &SendClientPort);
    SendClientPort = nullptr;
}

BOOLEAN
WhitelistProcess(HANDLE ProcessId)
{
    PLIST_ENTRY TempList = 0;

    //
    // check if the operation is previously in the process list or not
    //
    TempList = &g_FileTraceList;
    while (&g_FileTraceList != TempList->Flink)
    {
        TempList                                   = TempList->Flink;
        PANTI_RANSOMWARE_FILE_TRACE ProcDetailItem = CONTAINING_RECORD(TempList, ANTI_RANSOMWARE_FILE_TRACE, FileTraceList);

        if (ProcDetailItem->ProcId == ProcessId)
        {
            //
            // Found a structure that matches the details or in other words, the
            // process previously deleted or changed a file
            //
            ProcDetailItem->IsWhitelisted = TRUE;
            return TRUE;
        }
    }

    return FALSE;
}

NTSTATUS
PortMessageNotify(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength, PULONG ReturnOutputBufferLength)
{
    PANTI_RANSOMWARE_FLT_IOCTL_REQUEST UserRequest;

    //
    // IOCTL Dispatcher
    //
    UserRequest = (PANTI_RANSOMWARE_FLT_IOCTL_REQUEST)InputBuffer;

    if (UserRequest == NULL)
    {
        //
        // Unknown erroor
        //
        return STATUS_UNSUCCESSFUL;
    }

    switch (UserRequest->IoctlRequest)
    {
    case IOCTL_REQUEST_PROCESS_ID_WHITELIST:

        //
        // Add user-porcess to the whitelist processes
        //
        if (WhitelistProcess((HANDLE)UserRequest->OptionalParam1))
        {
            UserRequest->KernelStatus = KERNEL_STATUS_SUCCESSFUL;
        }
        else
        {
            UserRequest->KernelStatus = KERNEL_STATUS_PRIMARY_DISK_ALREADY_EXISTS;
        }

        break;
    case IOCTL_REGISTER_EXTENSIONS:

        //
        // *** Initialize the extensions ***
        //
        if (g_IsExtensionBuffersInitialized)
        {
            return STATUS_UNSUCCESSFUL;
        }

        //
        // Allocate the buffer for the array of extensions
        // (we multiply it by 2 because each character in the
        // wide-range occupies 2 bytes)
        //
        g_ExtensionBuffers = (UINT64)ExAllocatePoolWithTag(NonPagedPool, SIZE_OF_EXTENSION_BUFFER, POOLTAG);

        if (g_ExtensionBuffers == NULL)
        {
            return STATUS_UNSUCCESSFUL;
        }
        RtlZeroMemory((PVOID)g_ExtensionBuffers, SIZE_OF_EXTENSION_BUFFER);

        //
        // Copy the buffer from user-mode to the kernel-mode buffers
        // we added sizeof(UINT32) because the start of the buffer conains
        // the ioctl code
        //
        RtlCopyBytes((PVOID)g_ExtensionBuffers, (PVOID)((UINT64)InputBuffer + sizeof(UINT32)), SIZE_OF_EXTENSION_BUFFER);

        //
        // Set that extensions buffers are already initialized
        //
        g_IsExtensionBuffersInitialized = TRUE;

        break;

    case IOCTL_SET_PRIMARY_DRIVE:

        if (g_IsPrimaryDiskAdded == FALSE)
        {
            g_PrimaryDiskBuffer = (UINT64)ExAllocatePoolWithTag(NonPagedPool, MAX_PATH, POOLTAG);

            if (g_PrimaryDiskBuffer == NULL)
            {
                UserRequest->KernelStatus = KERNEL_STATUS_PRIMARY_DISK_ALREADY_EXISTS;
                return STATUS_UNSUCCESSFUL;
            }

            RtlZeroMemory((PVOID)g_PrimaryDiskBuffer, MAX_PATH);

            //
            // copy the user-mode to primary disk buffer
            //
            RtlCopyMemory((PVOID)g_PrimaryDiskBuffer, (PVOID)((UINT64)InputBuffer + sizeof(UINT32)), MAX_PATH);

            g_IsPrimaryDiskAdded      = TRUE;
            UserRequest->KernelStatus = KERNEL_STATUS_SUCCESSFUL;
        }
        else
        {
            UserRequest->KernelStatus = KERNEL_STATUS_PRIMARY_DISK_ALREADY_EXISTS;
        }

        break;
    default:
        UserRequest->KernelStatus = KERNEL_STATUS_INVALID_IOCTL;
        break;
    }

    return STATUS_SUCCESS;
}

/**
 * @brief This routine is called at the start of instance teardown.
 *
 * @param FltObjects Pointer to the FLT_RELATED_OBJECTS data structure containing
 * opaque handles to this filter, instance and its associated volume.
 * @param Flags Reason why this instance is being deleted.
 * @return VOID
 */
VOID
SystemMonInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS       FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    DbgPrint("SystemMon!SystemMonInstanceTeardownStart: Entered\n");
}

/**
 * @brief  This routine is called at the end of instance teardown.
 *
 * @param FltObjects Pointer to the FLT_RELATED_OBJECTS data structure containing
 * opaque handles to this filter, instance and its associated volume.
 * @param Flags Reason why this instance is being deleted.
 * @return VOID
 */
VOID
SystemMonInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS       FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    DbgPrint("SystemMon!SystemMonInstanceTeardownComplete: Entered\n");
}

/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/

/**
 * @brief This is the initialization routine for this miniFilter driver.  This
 * registers with FltMgr and initializes all global data structures.
 *
 * @param DriverObject Pointer to driver object created by the system to
 * represent this driver.
 * @param RegistryPath Unicode string identifying where the parameters for this
 * driver are located in the registry.
 * @return NTSTATUS Routine can return non success error codes.
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("SystemMon!DriverEntry: Entered\n");

    //
    //  Register with FltMgr to tell it our callback routines
    //
    status = FltRegisterFilter(DriverObject,
                               &FilterRegistration,
                               &gFilterHandle);

    FLT_ASSERT(NT_SUCCESS(status));
    if (!NT_SUCCESS(status))
        return status;

    //
    // Initialize the list of file trace
    //
    InitializeListHead(&g_FileTraceList);

    do
    {
        UNICODE_STRING       name = RTL_CONSTANT_STRING(L"\\SystemMonPort");
        PSECURITY_DESCRIPTOR sd;

        status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
        if (!NT_SUCCESS(status))
            break;

        OBJECT_ATTRIBUTES attr;
        InitializeObjectAttributes(&attr, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, sd);

        status = FltCreateCommunicationPort(gFilterHandle, &FilterPort, &attr, nullptr, PortConnectNotify, PortDisconnectNotify, PortMessageNotify, 1);

        FltFreeSecurityDescriptor(sd);
        if (!NT_SUCCESS(status))
            break;

        //
        //  Start filtering i/o
        //
        status = FltStartFiltering(gFilterHandle);

    } while (false);

    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(gFilterHandle);
    }

    return status;
}

/**
 * @brief This is the unload routine for this miniFilter driver. This is called
 *	when the minifilter is about to be unloaded. We can fail this unload
 *	request if this is not a mandatory unload indicated by the Flags
 *	parameter.
 *
 * @param Flags Indicating if this is a mandatory unload.
 * @return NTSTATUS Returns STATUS_SUCCESS.
 */
NTSTATUS
SystemMonUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    PAGED_CODE();

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("SystemMon!SystemMonUnload: Entered\n"));

    FltCloseCommunicationPort(FilterPort);
    FltUnregisterFilter(gFilterHandle);

    return STATUS_SUCCESS;
}

/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/

/**
 * @brief This routine is the post-operation completion routine for this
 *	miniFilter.
 * @details This is non-pageable because it may be called at DPC level.
 *
 * @param Data Pointer to the filter callbackData that is passed to us.
 * @param FltObjects Pointer to the FLT_RELATED_OBJECTS data structure
 * containing opaque handles to this filter, instance, its associated
 * volume and file object.
 * @param CompletionContext The completion context set in the
 * pre-operation routine.
 * @param Flags Denotes whether the completion is successful or is
 *  being drained.
 * @return FLT_POSTOP_CALLBACK_STATUS The return value is the status of the operation.
 */
FLT_POSTOP_CALLBACK_STATUS
SystemMonPostOperation(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_ PCFLT_RELATED_OBJECTS    FltObjects,
    _In_opt_ PVOID                CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
                 ("SystemMon!SystemMonPostOperation: Entered\n"));

    return FLT_POSTOP_FINISHED_PROCESSING;
}

/**
 * @brief This routine is a pre-operation dispatch routine for this miniFilter.
 * @details This is non-pageable because it could be called on the paging path
 *
 * @param Data Pointer to the filter callbackData that is passed to us.
 * @param FltObjects Pointer to the FLT_RELATED_OBJECTS data structure containing
 * opaque handles to this filter, instance, its associated volume and
 * file object.
 * @param CompletionContext The context for the completion routine for this
 * operation.
 * @return FLT_PREOP_CALLBACK_STATUS The return value is the status of the
 * operation.
 */
FLT_PREOP_CALLBACK_STATUS
SystemMonPreOperationNoPostOperation(
    _Inout_ PFLT_CALLBACK_DATA     Data,
    _In_ PCFLT_RELATED_OBJECTS     FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID * CompletionContext)
{
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    DbgPrint("SystemMon!SystemMonPreOperationNoPostOperation: Entered\n");

    //
    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.
    //
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

BOOLEAN
AddAndCheckSuspectOperation(OPERATION_TYPE Operation, PBOOLEAN IsProcessWhiteListed)
{
    PLIST_ENTRY                 TempList = 0;
    HANDLE                      CurrentProcId;
    PEPROCESS                   CurrentEprocess;
    BOOLEAN                     FoundPreviousStructure = FALSE;
    PANTI_RANSOMWARE_FILE_TRACE CurrentItem            = 0;

    PAGED_CODE();

    CurrentProcId   = PsGetCurrentProcessId();
    CurrentEprocess = PsGetCurrentProcess();

    //
    // By default the IsProcessWhiteListed is FALSE as we're not trying to
    // to whitelist processes that are not yet added to the process trace
    // list
    //
    *IsProcessWhiteListed = FALSE;

    //
    // check if the operation is previously in the process list or not
    //
    TempList = &g_FileTraceList;
    while (&g_FileTraceList != TempList->Flink)
    {
        TempList                                   = TempList->Flink;
        PANTI_RANSOMWARE_FILE_TRACE ProcDetailItem = CONTAINING_RECORD(TempList, ANTI_RANSOMWARE_FILE_TRACE, FileTraceList);

        if (ProcDetailItem->ProcId == CurrentProcId && ProcDetailItem->ProcessStruct == CurrentEprocess)
        {
            //
            // Find a structure that matches the details or in other words, the
            // process previously deleted or changed a file
            //
            CurrentItem = ProcDetailItem;

            //
            // Check the structures to see whether the process is whitelisted or not
            //
            if (ProcDetailItem->IsWhitelisted)
            {
                //
                // Whitelisted
                //
                *IsProcessWhiteListed = TRUE;
            }

            //
            // Indicate the the structure is found
            //
            FoundPreviousStructure = TRUE;
            break;
        }
    }

    if (!FoundPreviousStructure)
    {
        //
        // It's first time that this process changed or modified
        // We should allocate the new structure
        //
        CurrentItem = (PANTI_RANSOMWARE_FILE_TRACE)ExAllocatePoolWithTag(NonPagedPool, sizeof(ANTI_RANSOMWARE_FILE_TRACE), POOLTAG);

        if (CurrentItem == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        //
        // Zero the buffer
        //
        RtlZeroBytes(CurrentItem, sizeof(ANTI_RANSOMWARE_FILE_TRACE));

        //
        // Fill the structure
        //
        CurrentItem->CountOfModificationsToSensitiveFiles = 0;
        CurrentItem->ProcId                               = CurrentProcId;
        CurrentItem->ProcessStruct                        = CurrentEprocess;

        //
        // Add it to the list
        //
        InsertHeadList(&g_FileTraceList, &(CurrentItem->FileTraceList));
    }

    //
    // Increase the count of modification
    //
    CurrentItem->CountOfModificationsToSensitiveFiles = CurrentItem->CountOfModificationsToSensitiveFiles + 1;

    //
    // Now, it's time to check whether everything is right or not
    //
    if (CurrentItem->CountOfModificationsToSensitiveFiles >= g_MaximumAllowed)
    {
        //
        // If the process is whitelisted there is no need to return TRUE
        //
        if (*IsProcessWhiteListed == FALSE)
        {
            return TRUE;
        }
    }
    return FALSE;
}

_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS
DelProtectPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *)
{
    //UNREFERENCED_PARAMETER(FltObjects);

    if (!g_SystemMonIsEnabled || Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;

    auto & params = Data->Iopb->Parameters.Create;

    if (params.Options & FILE_DELETE_ON_CLOSE)
    {
        //
        // delete operation
        // KdPrint(("Delete on close: %wZ\n", &FltObjects->FileObject->FileName));
        //
        if (!IsDeleteAllowed(Data, OPERATION_DELETE_FILE_ON_CLOSE, FltObjects))
        {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            return FLT_PREOP_COMPLETE;
        }
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS
DelProtectPreSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID * CompletionContext)
{
    // UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!g_SystemMonIsEnabled || Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    auto & params = Data->Iopb->Parameters.SetFileInformation;

    if (params.FileInformationClass != FileDispositionInformation && params.FileInformationClass != FileDispositionInformationEx)
    {
        //
        // not a delete operation
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    auto info = (FILE_DISPOSITION_INFORMATION *)params.InfoBuffer;
    if (!info->DeleteFile)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (IsDeleteAllowed(Data, OPERATION_DELETE_FILE_SET_INFORMATION, FltObjects))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    return FLT_PREOP_COMPLETE;
}

bool
IsDeleteAllowed(_In_ PFLT_CALLBACK_DATA Data, OPERATION_TYPE Operation, PCFLT_RELATED_OBJECTS FltObjects)
{
    NTSTATUS                   Status;
    BOOLEAN                    Allow;
    PFLT_FILE_NAME_INFORMATION nameInfo = nullptr;

    do
    {
        auto status = FltGetFileNameInformation(Data, FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_NORMALIZED, &nameInfo);
        if (!NT_SUCCESS(status))
            break;

        status = FltParseFileNameInformation(nameInfo);

        if (!NT_SUCCESS(status))
            break;

        //
        // Concatenate volume+share+directory
        //
        UNICODE_STRING path;
        path.Length = path.MaximumLength = /* nameInfo->Volume.Length + nameInfo->Share.Length + nameInfo->ParentDir.Length + */ nameInfo->Name.Length;
        path.Buffer                      = nameInfo->Volume.Buffer;

        //
        // KdPrint(("Checking directory: %wZ\n", &path));
        //
        Allow = CentralCheck(&path, NULL, Operation);

    } while (false);

    if (nameInfo)
        FltReleaseFileNameInformation(nameInfo);

    return Allow;
}
