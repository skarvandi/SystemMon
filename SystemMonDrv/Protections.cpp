
#include "pch.h"

extern BOOLEAN g_IsExtensionBuffersInitialized;
extern UINT64  g_ExtensionBuffers;
extern BOOLEAN g_IsPrimaryDiskAdded;
extern UINT64  g_PrimaryDiskBuffer;

void
ConcatBackupStringToTheVolumeName(wchar_t * TargetBuffer, PINT32 LengthOfBackup)
{
    int lengthOfBackupDir     = wcslen(SystemMonProtectedFolder) * 2;
    int lengthOfUnicodeBuffer = wcslen(TargetBuffer) * 2;

    int OccuranceOfSlash = 0;

    for (size_t i = 0; i < lengthOfUnicodeBuffer; i += 2)
    {
        wchar_t Temp = *((wchar_t *)((UINT64)TargetBuffer + i));

        if (Temp == '\\')
        {
            OccuranceOfSlash++;

            if (OccuranceOfSlash == 3)
            {
                i += 2;

                UINT64 SpaceBetweenTwoPath = (UINT64)TargetBuffer + i;

                //
                // We reach to the end of the HarddiskVolumeXX
                //
                RtlMoveMemory((PVOID)(SpaceBetweenTwoPath + lengthOfBackupDir),
                              (PVOID)(SpaceBetweenTwoPath),
                              lengthOfUnicodeBuffer - i);

                //
                // Clean the between space
                //
                RtlZeroMemory((PVOID)SpaceBetweenTwoPath, lengthOfBackupDir);

                //
                // Concat the string
                //
                RtlCopyMemory((PVOID)SpaceBetweenTwoPath, SystemMonProtectedFolder, lengthOfBackupDir);

                //
                // Set the  buffer
                //
                *LengthOfBackup = lengthOfBackupDir;

                //
                // Break from the loop
                //
                break;
            }
        }
    }
}

NTSTATUS
BackupFile(PUNICODE_STRING FileName, PCFLT_RELATED_OBJECTS FltObjects, BOOLEAN FromDeleteRoutines, PUNICODE_STRING PathInTheCaseOfDeletion)
{
    HANDLE          hTargetFile = nullptr;
    HANDLE          hSourceFile = nullptr;
    IO_STATUS_BLOCK ioStatus;
    auto            status       = STATUS_SUCCESS;
    void *          buffer       = nullptr;
    int             backupBuffer = 0;
    int             tempSplit    = 0;

    if (FromDeleteRoutines)
    {
        //
        // It's coming from a deletion routine
        //
        UNICODE_STRING targetFileName;

        targetFileName.Buffer = (WCHAR *)ExAllocatePoolWithTag(PagedPool, MAX_PATH, DRIVER_TAG);
        if (targetFileName.Buffer == nullptr)
            return STATUS_INSUFFICIENT_RESOURCES;

        //
        // Zero the memory
        //
        RtlZeroMemory(targetFileName.Buffer, MAX_PATH);

        targetFileName.Length        = PathInTheCaseOfDeletion->Length;
        targetFileName.MaximumLength = MAX_PATH - 2;

        RtlCopyUnicodeString(&targetFileName, PathInTheCaseOfDeletion);

        ConcatBackupStringToTheVolumeName(targetFileName.Buffer, &backupBuffer);

        targetFileName.Length += backupBuffer;
        targetFileName.MaximumLength += backupBuffer;

        if (IsFileExists(&targetFileName))
        {
            AppendPostFixAndCheckIfFileExists(&targetFileName);
        }

        CopyFile(PathInTheCaseOfDeletion, &targetFileName);

        if (targetFileName.Buffer)
            ExFreePool(targetFileName.Buffer);
    }
    else
    {
        //
        // get source file size
        //
        LARGE_INTEGER fileSize;
        status = FsRtlGetFileSize(FltObjects->FileObject, &fileSize);
        if (!NT_SUCCESS(status) || fileSize.QuadPart == 0)
            return status;

        do
        {
            //
            // open source file
            //
            OBJECT_ATTRIBUTES sourceFileAttr;
            InitializeObjectAttributes(&sourceFileAttr, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            status = FltCreateFile(
                FltObjects->Filter,           // filter object
                FltObjects->Instance,         // filter instance
                &hSourceFile,                 // resulting handle
                FILE_READ_DATA | SYNCHRONIZE, // access mask
                &sourceFileAttr,              // object attributes
                &ioStatus,                    // resulting status
                nullptr,
                FILE_ATTRIBUTE_NORMAL,                               // allocation size, file attributes
                FILE_SHARE_READ | FILE_SHARE_WRITE,                  // share flags
                FILE_OPEN,                                           // create disposition
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_SEQUENTIAL_ONLY, // create options (sync I/O)
                nullptr,
                0,                             // extended attributes, EA length
                IO_IGNORE_SHARE_ACCESS_CHECK); // flags

            if (!NT_SUCCESS(status))
                break;

            //
            // open target file
            //
            UNICODE_STRING targetFileName;
            targetFileName.MaximumLength = FileName->Length;

            targetFileName.Buffer        = (WCHAR *)ExAllocatePoolWithTag(PagedPool, MAX_PATH, DRIVER_TAG);
            targetFileName.MaximumLength = MAX_PATH - 2;
            if (targetFileName.Buffer == nullptr)
                return STATUS_INSUFFICIENT_RESOURCES;

            //
            // Zero the memory
            //
            RtlZeroMemory(targetFileName.Buffer, MAX_PATH);

            RtlCopyUnicodeString(&targetFileName, FileName);

            ConcatBackupStringToTheVolumeName(targetFileName.Buffer, &backupBuffer);

            targetFileName.Length += backupBuffer;
            // targetFileName.MaximumLength += backupBuffer;

            if (IsFileExists(&targetFileName))
            {
                AppendPostFixAndCheckIfFileExists(&targetFileName);
            }

            OBJECT_ATTRIBUTES targetFileAttr;
            InitializeObjectAttributes(&targetFileAttr, &targetFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            status = FltCreateFile(
                FltObjects->Filter,          // filter object
                FltObjects->Instance,        // filter instance
                &hTargetFile,                // resulting handle
                GENERIC_WRITE | SYNCHRONIZE, // access mask
                &targetFileAttr,             // object attributes
                &ioStatus,                   // resulting status
                nullptr,
                FILE_ATTRIBUTE_NORMAL,                               // allocation size, file attributes
                0,                                                   // share flags
                FILE_SUPERSEDE,                                      // create disposition
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_SEQUENTIAL_ONLY, // create options (sync I/O)
                nullptr,
                0,                                   // extended attributes, EA length
                0 /*IO_IGNORE_SHARE_ACCESS_CHECK*/); // flags

            if (status == STATUS_OBJECT_PATH_NOT_FOUND)
            {
                //
                // Path not found, we should create folder first
                //
                int targetFileNameInitialLength = targetFileName.Length;

                //
                // Loop to create folders
                //
                for (size_t i = 0; i < targetFileNameInitialLength; i += 2)
                {
                    wchar_t Temp = *((wchar_t *)((UINT64)targetFileName.Buffer + i));

                    if (Temp == '\\')
                    {
                        tempSplit++;

                        if (tempSplit <= 3)
                        {
                            continue;
                        }
                        targetFileName.Length = i;

                        //
                        // Create directory
                        //
                        OBJECT_ATTRIBUTES targetFileAttr;
                        InitializeObjectAttributes(&targetFileAttr, &targetFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

                        status = FltCreateFile(
                            FltObjects->Filter,   // filter object
                            FltObjects->Instance, // filter instance
                            &hTargetFile,         // resulting handle
                            GENERIC_WRITE,        // access mask
                            &targetFileAttr,      // object attributes
                            &ioStatus,            // resulting status
                            nullptr,
                            FILE_ATTRIBUTE_NORMAL, // allocation size, file attributes
                            0,                     // share flags
                            FILE_CREATE,           // create disposition (If the file already exists,
                                                   // fail the request and do not create or open the
                                                   // given file. If it does not exist, create the given file.)
                            FILE_DIRECTORY_FILE,   // create options (sync I/O)
                            nullptr,
                            0,                                   // extended attributes, EA length
                            0 /*IO_IGNORE_SHARE_ACCESS_CHECK*/); // flags

                        if (NT_SUCCESS(status))
                        {
                            FltClose(hTargetFile);
                        }
                    }
                }

                //
                // Try one time more with create directories !
                //
                targetFileName.Length = targetFileNameInitialLength;

                OBJECT_ATTRIBUTES targetFileAttr;
                InitializeObjectAttributes(&targetFileAttr, &targetFileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

                status = FltCreateFile(
                    FltObjects->Filter,          // filter object
                    FltObjects->Instance,        // filter instance
                    &hTargetFile,                // resulting handle
                    GENERIC_WRITE | SYNCHRONIZE, // access mask
                    &targetFileAttr,             // object attributes
                    &ioStatus,                   // resulting status
                    nullptr,
                    FILE_ATTRIBUTE_NORMAL,                               // allocation size, file attributes
                    0,                                                   // share flags
                    FILE_SUPERSEDE,                                      // create disposition
                    FILE_SYNCHRONOUS_IO_NONALERT | FILE_SEQUENTIAL_ONLY, // create options (sync I/O)
                    nullptr,
                    0,                                   // extended attributes, EA length
                    0 /*IO_IGNORE_SHARE_ACCESS_CHECK*/); // flags
            }

            ExFreePool(targetFileName.Buffer);

            if (!NT_SUCCESS(status))
                break;

            //
            // allocate buffer for copying purposes
            //
            buffer = ExAllocatePoolWithTag(PagedPool, MAXIMUM_SIZE_OF_FILE_TO_BACKUP, DRIVER_TAG);
            if (!buffer)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            //
            // loop - read from source, write to target
            //
            LARGE_INTEGER offset      = {0}; // read
            LARGE_INTEGER writeOffset = {0}; // write

            ULONG bytes;
            auto  saveSize = fileSize;
            while (fileSize.QuadPart > 0)
            {
                status = ZwReadFile(
                    hSourceFile,
                    nullptr, // optional KEVENT
                    nullptr,
                    nullptr, // no APC
                    &ioStatus,
                    buffer,
                    (ULONG)min((LONGLONG)MAXIMUM_SIZE_OF_FILE_TO_BACKUP, fileSize.QuadPart), // # of bytes
                    &offset,                                                                 // offset
                    nullptr);                                                                // optional key
                if (!NT_SUCCESS(status))
                    break;

                bytes = (ULONG)ioStatus.Information;

                //
                // write to target file
                //
                status = ZwWriteFile(
                    hTargetFile, // target handle
                    nullptr,     // optional KEVENT
                    nullptr,
                    nullptr,      // APC routine, APC context
                    &ioStatus,    // I/O status result
                    buffer,       // data to write
                    bytes,        // # bytes to write
                    &writeOffset, // offset
                    nullptr);     // optional key

                if (!NT_SUCCESS(status))
                    break;

                //
                // update byte count and offsets
                //
                offset.QuadPart += bytes;
                writeOffset.QuadPart += bytes;
                fileSize.QuadPart -= bytes;
            }

            FILE_END_OF_FILE_INFORMATION info;
            info.EndOfFile = saveSize;
            NT_VERIFY(NT_SUCCESS(ZwSetInformationFile(hTargetFile, &ioStatus, &info, sizeof(info), FileEndOfFileInformation)));
        } while (false);

        if (buffer)
            ExFreePool(buffer);
        if (hSourceFile)
            FltClose(hSourceFile);
        if (hTargetFile)
            FltClose(hTargetFile);
    }
    return status;
}

bool
IsProtectedBackupFile(PCUNICODE_STRING directory)
{
    //
    // no counted version of wcsstr :(
    //
    ULONG maxSize = 1024;
    if (directory->Length > maxSize)
        return false;

    auto copy = (WCHAR *)ExAllocatePoolWithTag(PagedPool, maxSize + sizeof(WCHAR), DRIVER_TAG);
    if (!copy)
        return false;

    RtlZeroMemory(copy, maxSize + sizeof(WCHAR));
    wcsncpy_s(copy, 1 + maxSize / sizeof(WCHAR), directory->Buffer, directory->Length / sizeof(WCHAR));
    _wcslwr(copy);
    bool ImmAction = wcsstr(copy, SystemMonProtectedFolder);

    ExFreePool(copy);

    return ImmAction;
}

bool
IsUserDirectory(PCUNICODE_STRING directory, PBOOLEAN ImmediateAction)
{
    wchar_t * splittedItem;
    wchar_t * next_token                                              = NULL;
    wchar_t   CurrentExtensionArray[MAXIMUM_LENGTH_OF_EACH_EXTENSION] = {0};

    //
    // no counted version of wcsstr :(
    //
    ULONG maxSize = 1024;
    if (directory->Length > maxSize)
        return false;

    auto copy = (WCHAR *)ExAllocatePoolWithTag(PagedPool, maxSize + sizeof(WCHAR), DRIVER_TAG);
    if (!copy)
        return false;

    RtlZeroMemory(copy, maxSize + sizeof(WCHAR));
    wcsncpy_s(copy, 1 + maxSize / sizeof(WCHAR), directory->Buffer, directory->Length / sizeof(WCHAR));
    _wcslwr(copy);

    bool doBackup = true;

    if (doBackup == false)
    {
        if (g_IsPrimaryDiskAdded)
        {
            doBackup = !wcsstr(copy, (wchar_t *)g_PrimaryDiskBuffer);

            //
            // Check if it's on primary disk
            //
            if (doBackup == true)
            {
                //
                // means that there is no primary disk on this file,
                // so probably it's for other drives. e.g. d:\ or anything
                // else, so we should create backup
                //
                doBackup = true;
            }
        }
    }

    bool ImmAction = wcsstr(copy, SystemMonProtectedFolder);

    if (ImmAction)
    {
        *ImmediateAction = TRUE;

        ExFreePool(copy);
        return TRUE;
    }
    else
    {
        *ImmediateAction = FALSE;
    }

    //
    // Check for protected extensions
    //
    if (doBackup)
    {
        //
        // *** Check for the extensions ***
        //

        //
        // Check through all possible extensions, by default we will
        // return TRUE (doBackup is TRUE) if the extensions buffer is
        // not already initialized
        //
        if (g_IsExtensionBuffersInitialized)
        {
            for (size_t i = 0; i < MAXIMUM_EXTENSIONS; i++)
            {
                UINT64 CurrentExtension = 0;

                //
                // If the entry is zero then we probably reached to the
                // end of the extension buffer, we should read
                // MAXIMUM_LENGTH_OF_EACH_EXTENSION Bytes of the buffer
                //
                memcpy(CurrentExtensionArray,
                       (PVOID)((UINT64)g_ExtensionBuffers + i * MAXIMUM_LENGTH_OF_EACH_EXTENSION * 2),
                       MAXIMUM_LENGTH_OF_EACH_EXTENSION * 2);

                //
                // It is because we want to use the Current Extension to
                // check whether we reached to the end of the buffer list
                // or not
                //
                memcpy(&CurrentExtension,
                       (PVOID)(g_ExtensionBuffers + i * MAXIMUM_LENGTH_OF_EACH_EXTENSION * 2),
                       sizeof(UINT64));

                if (CurrentExtension == NULL)
                {
                    //
                    // We probably reached to the end of the extensions
                    //
                    doBackup = FALSE;
                    break;
                }
                else
                {
                    //
                    // Otherwise, it's an extension, we have to see whether
                    // this extension that we checked or not
                    //
                    doBackup = wcsstr(copy, CurrentExtensionArray);

                    if (doBackup)
                    {
                        //
                        // We found the extension in the list
                        // doBackup is true too, no need to set
                        // it to the TRUE but we set it to make code more readable
                        //
                        doBackup = TRUE;
                        break;
                    }
                }
            }
        }
    }

    ExFreePool(copy);

    return doBackup;
}

NTSTATUS
CreateDirectory(PUNICODE_STRING dirName)
{
    IO_STATUS_BLOCK   iosb;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS          Status;
    HANDLE            FileHandle = NULL;
    FILE_OBJECT *     FileObj;

    InitializeObjectAttributes(
        &ObjectAttributes,
        dirName,
        (OBJ_CASE_INSENSITIVE |
         OBJ_KERNEL_HANDLE),
        NULL,
        NULL);

    Status = ZwCreateFile(
        &FileHandle,
        GENERIC_READ,
        &ObjectAttributes,
        &iosb,
        0,
        FILE_ATTRIBUTE_NORMAL | SYNCHRONIZE,
        FILE_SHARE_WRITE | FILE_SHARE_READ,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
        NULL,
        0);

    if (FileHandle)
    {
        ZwClose(FileHandle);
    }

    return Status;
}

VOID
AppendPostFixAndCheckIfFileExists(PUNICODE_STRING targetFileName)
{
    UNICODE_STRING targetFileNameBackup;

    UINT32 Index = 0;

    //
    // We have to create a copy of the target buffer
    //
    targetFileNameBackup.Buffer = (WCHAR *)ExAllocatePoolWithTag(PagedPool, MAX_PATH, DRIVER_TAG);
    if (targetFileNameBackup.Buffer == nullptr)
        return;

    while (Index < 0xfffffffe)
    {
        //
        // Zero the memory
        //
        RtlZeroMemory(targetFileNameBackup.Buffer, MAX_PATH);

        targetFileNameBackup.MaximumLength = MAX_PATH - 2;

        RtlCopyUnicodeString(&targetFileNameBackup, targetFileName);

        DECLARE_UNICODE_STRING_SIZE(AppendingName, 30);

        NTSTATUS NtStatus = RtlIntegerToUnicodeString(Index, 10, &AppendingName);

        NtStatus = RtlAppendUnicodeStringToString(&targetFileNameBackup, &AppendingName);

        if (IsFileExists(&targetFileNameBackup))
        {
            //
            // File exists
            //
            Index++;
            continue;
        }
        else
        {
            //
            // We got the right index
            //
            DECLARE_UNICODE_STRING_SIZE(AppendingName2, 30);

            NTSTATUS NtStatus = RtlIntegerToUnicodeString(Index, 10, &AppendingName2);

            NtStatus = RtlAppendUnicodeStringToString(targetFileName, &AppendingName2);

            //
            // Get out of while loop
            //
            break;
        }
    }

    //
    // make sure that we freed the buffer
    //

    ExFreePool(targetFileNameBackup.Buffer);
}

BOOLEAN
IsFileExists(PUNICODE_STRING dirName)
{
    IO_STATUS_BLOCK   iosb;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS          Status;
    HANDLE            FileHandle = NULL;
    FILE_OBJECT *     FileObj;

    InitializeObjectAttributes(
        &ObjectAttributes,
        dirName,
        (OBJ_CASE_INSENSITIVE |
         OBJ_KERNEL_HANDLE),
        NULL,
        NULL);

    Status = ZwCreateFile(&FileHandle,
                          GENERIC_READ | SYNCHRONIZE,
                          &ObjectAttributes,
                          &iosb,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE,
                          NULL,
                          0);

    if (NT_SUCCESS(Status))
    {
        //
        // File Exist
        //
        if (FileHandle)
        {
            ZwClose(FileHandle);
        }

        return TRUE;
    }

    //
    // File doesn't exist
    //
    return FALSE;
}

NTSTATUS
CopyFile(PUNICODE_STRING SourceFile, PUNICODE_STRING DestinationFile)
{
    OBJECT_ATTRIBUTES objAttrSrc;
    OBJECT_ATTRIBUTES objAttrDest;
    size_t            cb = 0;
    LARGE_INTEGER     byteOffset;
    HANDLE            handle;
    NTSTATUS          ntstatus;
    IO_STATUS_BLOCK   ioStatusBlock;
    UINT32            tempSplit = 0;

    //
    // Do not try to perform any file operations at higher IRQL levels.
    // Instead, you may use a work item or a system worker thread to
    // perform file operations.
    //

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    //
    // Allocate buffer to store the file
    //
    CHAR * buffer = (CHAR *)ExAllocatePoolWithTag(NonPagedPool, MAXIMUM_SIZE_OF_FILE_TO_BACKUP, POOLTAG);

    if (buffer == NULL)
    {
        return STATUS_UNSUCCESSFUL;
    }

    RtlZeroMemory(buffer, MAXIMUM_SIZE_OF_FILE_TO_BACKUP);

    // RtlInitUnicodeString(&uniName, L"\\DosDevices\\C:\\WINDOWS\\example.txt");  // or L"\\SystemRoot\\example.txt"
    // RtlInitUnicodeString(&uniName, L"\\Device\\HarddiskVolume2\\Users\\sina\\Desktop\\backup.txt");  // or L"\\SystemRoot\\example.txt"
    InitializeObjectAttributes(&objAttrSrc, SourceFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    InitializeObjectAttributes(&objAttrDest, DestinationFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    ///////////////////////////////////////////////////

    ntstatus = ZwCreateFile(&handle,
                            GENERIC_READ | SYNCHRONIZE,
                            &objAttrSrc,
                            &ioStatusBlock,
                            NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            FILE_OPEN,
                            FILE_NON_DIRECTORY_FILE,
                            NULL,
                            0);

    if (NT_SUCCESS(ntstatus))
    {
        byteOffset.LowPart = byteOffset.HighPart = 0;
        ntstatus                                 = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, buffer, MAXIMUM_SIZE_OF_FILE_TO_BACKUP, &byteOffset, NULL);

        if (NT_SUCCESS(ntstatus))
        {
            //
            // I/O status block contains number of read bytes
            //
            cb = ioStatusBlock.Information;
            ZwClose(handle);
        }
    }

    ///////////////////////////////////////////////////

    //
    // Check if the file is empty then we don't need to
    // create backup from it
    //
    if (cb != 0)
    {
        ////////////////////////// Create Directory //////////////////////////////

        ntstatus = ZwCreateFile(&handle,
                                GENERIC_WRITE,
                                &objAttrDest,
                                &ioStatusBlock,
                                NULL,
                                FILE_ATTRIBUTE_NORMAL,
                                0,
                                FILE_OPEN_IF,
                                FILE_SYNCHRONOUS_IO_NONALERT,
                                NULL,
                                0);

        if (NT_SUCCESS(ntstatus))
        {
            ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, buffer, cb, NULL, NULL);
            ZwClose(handle);
        }

        if (ntstatus == STATUS_OBJECT_PATH_NOT_FOUND)
        {
            //
            // Path not found, we should create folder first
            //
            int targetFileNameInitialLength = DestinationFile->Length;

            //
            // Loop to create folders
            //
            for (size_t i = 0; i < targetFileNameInitialLength; i += 2)
            {
                wchar_t Temp = *((wchar_t *)((UINT64)DestinationFile->Buffer + i));

                if (Temp == '\\')
                {
                    tempSplit++;

                    if (tempSplit <= 3)
                    {
                        continue;
                    }
                    DestinationFile->Length = i;

                    //
                    // Create directory
                    //
                    CreateDirectory(DestinationFile);
                }
            }

            //
            // Try one time more with create directories !
            //
            DestinationFile->Length = targetFileNameInitialLength;

            //
            // Write the original file
            //
            ntstatus = ZwCreateFile(&handle,
                                    GENERIC_WRITE,
                                    &objAttrDest,
                                    &ioStatusBlock,
                                    NULL,
                                    FILE_ATTRIBUTE_NORMAL,
                                    0,
                                    FILE_OPEN_IF,
                                    FILE_SYNCHRONOUS_IO_NONALERT,
                                    NULL,
                                    0);

            if (NT_SUCCESS(ntstatus))
            {
                ntstatus = ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, buffer, cb, NULL, NULL);
                ZwClose(handle);
            }
        }
        ////////////////////////// End Create Directory //////////////////////////
    }
    ///////////////////////////////////////////////////
    //
    // De-allocate the allocated pool
    //
    ExFreePoolWithTag(buffer, POOLTAG);
}
