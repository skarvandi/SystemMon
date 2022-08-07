// SystemMon.cpp : This file contains the 'main' function. Program
// execution begins and ends there.
//

#include "pch.h"

#include "..\SystemMon\SystemMonCommon.h"

#pragma comment(lib, "Shlwapi.lib")

using namespace std;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
vector<ANTI_RANSOMWARE_PROCESS_TRACE> ProcessTrace;

#define MaximumCommandSize (MAX_PATH + MAX_PATH + MAX_PATH) * 2

BOOLEAN RegisterProcessToWhitelist(HANDLE CommunicationPort, UINT32 ProcessId);

#pragma comment(lib, "fltlib")
#pragma comment(lib, "ntdll.lib")

#define DeleteAfterXHours 7
#define GUI_APP_NAME L"ar-gui.exe"

EXTERN_C NTSTATUS NTAPI RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
EXTERN_C NTSTATUS NTAPI NtSetInformationProcess(HANDLE, ULONG, PVOID, ULONG);

//
// Return time difference in units of 100 us
//
INT64 DeltaHours(const SYSTEMTIME st1, const SYSTEMTIME st2) {

  union timeunion {
    FILETIME fileTime;
    ULARGE_INTEGER ul;
  };

  timeunion ft1;
  timeunion ft2;

  SystemTimeToFileTime(&st1, &ft1.fileTime);
  SystemTimeToFileTime(&st2, &ft2.fileTime);
  INT64 Res = ((ft2.ul.QuadPart - ft1.ul.QuadPart) / 10000000 / 3600);
  return Res;
}

VOID DirListFilesAndDelete(const wchar_t *startDir) {

  HANDLE hFind;
  WIN32_FIND_DATAW wfd;
  SYSTEMTIME CurrentLocalTime;
  UINT64 HoursPassedBeforeLastWrite;
  wchar_t *path;
  wchar_t *pathFileAddressToBeRemoved;

  path = (wchar_t *)malloc(MAX_PATH * 2);

  wsprintf(path, L"%ws\\*", startDir);

  fprintf(stdout, "In Directory \"%ws\"\n\n", startDir);
  hFind = FindFirstFileW(path, &wfd);

  if (hFind == INVALID_HANDLE_VALUE) {
    fprintf(stderr, "FindFirstFIle failed on path = \"%ws\"\n", path);
  }

  BOOL cont = TRUE;
  while (cont == TRUE) {
    if ((wcsncmp(L".", wfd.cFileName, 1) != 0) &&
        (wcsncmp(L"..", wfd.cFileName, 2) != 0)) {
      if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        wsprintf(path, L"%s\\%s", startDir, wfd.cFileName);

        if (PathIsDirectoryEmptyW(path)) {

          //
          // Directory is empty, let's delete it
          //
          RemoveDirectoryW(path);

        } else {
          //
          // The directory is not empty
          //
          DirListFilesAndDelete(path);
        }
      } else {

        //
        // Parse files
        //
        fprintf(stdout, "File = %ws\\%ws", startDir, wfd.cFileName);

        //
        // Find last write file time
        //
        SYSTEMTIME stUTC, stLocal;

        //
        // Convert the last-write time to local time.
        //
        FileTimeToSystemTime(&wfd.ftLastWriteTime, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

        //
        // Build a string showing the date and time.
        //
        GetSystemTime(&CurrentLocalTime);
        HoursPassedBeforeLastWrite = DeltaHours(stUTC, CurrentLocalTime);

        printf(
            "\t\t Last Write Date : %02d/%02d/%d  %02d:%02d \t Delta : %lld\n",
            stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour,
            stLocal.wMinute, HoursPassedBeforeLastWrite);

        if (HoursPassedBeforeLastWrite > DeleteAfterXHours * 24) {

          pathFileAddressToBeRemoved = (wchar_t *)malloc(MAX_PATH * 2);

          swprintf_s(pathFileAddressToBeRemoved, MAX_PATH, L"%ws\\%ws",
                     startDir, wfd.cFileName);

          //
          // The file should be deleted !
          //
          DeleteFileW(pathFileAddressToBeRemoved);

          //
          //
          //
          free(pathFileAddressToBeRemoved);
        }
      }
    }
    cont = FindNextFile(hFind, &wfd);
  }

  if (GetLastError() != ERROR_NO_MORE_FILES) {
    fprintf(stderr, "FindNextFile died for some reason; path = \"%ws\"\n",
            path);
  }
  if (FindClose(hFind) == FALSE) {
    fprintf(stderr, "FindClose failed\n");
  }
  free(path);
}

std::vector<std::string> GetAllDrives() {

  //
  // Check all the drivers avaiable
  //
  std::vector<std::string> arrayOfDrives;
  char *szDrives = new char[MAX_PATH]();
  if (GetLogicalDriveStringsA(MAX_PATH, szDrives))
    ;
  for (int i = 0; i < 100; i += 4)
    if (szDrives[i] != (char)0)
      arrayOfDrives.push_back(
          std::string{szDrives[i], szDrives[i + 1], szDrives[i + 2]});
  delete[] szDrives;
  return arrayOfDrives;
}

BOOLEAN IsDirExists(wchar_t *dirName_in) {

  DWORD ftyp = GetFileAttributesW(dirName_in);
  if (ftyp == INVALID_FILE_ATTRIBUTES)
    return false; // something is wrong with your path!

  if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
    return true; // this is a directory!

  return false; // this is not a directory!
}

BOOLEAN CheckAndDeleteBackup() {

  std::vector<std::string> drives = GetAllDrives();

  wchar_t Path[MAX_PATH] = {0};

  for (std::string currentDrive : drives) {

    std::wstring widestr =
        std::wstring(currentDrive.begin(), currentDrive.end());

    swprintf_s(Path, L"%s%s", widestr.c_str(), AntiRansomProtectedFolder);

    //
    // Check if the target
    //
    if (IsDirExists(Path)) {

      //
      // The path exists, it means that we have created some backups
      // on this drive before
      //
      printf("Path : %ws\n", Path);

      //
      // List and delete all old file on the target path
      //
      DirListFilesAndDelete(Path);
    }
  }

  return TRUE;
}

void SetProcessAsCritical() {

  ULONG BreakOnTermination;
  NTSTATUS status;

  BreakOnTermination = 1;

  status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination,
                                   sizeof(ULONG));

  if (status != 0) {
    printf("NtSetInformationProcess failed with status %#x\n\n", status);
  }

  else {
    printf("Enabled Successfully.\n");
  }
}

void UnSetProcessAsCritical() {

  ULONG BreakOnTermination;
  NTSTATUS status;

  BreakOnTermination = 0;

  status = NtSetInformationProcess((HANDLE)-1, 0x1d, &BreakOnTermination,
                                   sizeof(ULONG));

  if (status != 0) {
    printf("NtSetInformationProcess failed with status %#x\n", status);
  }

  else {
    printf("Canceled Successfully\n");
  }
}

BOOL EnableSeDebugPrivilege() {
  BOOLEAN bl;
  if (!NT_SUCCESS(RtlAdjustPrivilege(20, TRUE, FALSE, &bl))) {
    printf("Error enabling SeDebugPrivilege. You have to run this program in "
           "an elevated console.");
    return FALSE;
  }
  return TRUE;
}

void Suspend(DWORD processId, bool IsSuspend) {
  HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

  THREADENTRY32 threadEntry;
  threadEntry.dwSize = sizeof(THREADENTRY32);

  Thread32First(hThreadSnapshot, &threadEntry);

  do {
    if (threadEntry.th32OwnerProcessID == processId) {
      HANDLE hThread =
          OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);

      if (IsSuspend) {
        SuspendThread(hThread);
      } else {
        ResumeThread(hThread);
      }

      CloseHandle(hThread);
    }
  } while (Thread32Next(hThreadSnapshot, &threadEntry));

  CloseHandle(hThreadSnapshot);
}

BOOLEAN DisplayBlockMessageBox(HANDLE ProcessId, WCHAR *AccessedFileName,
                               WCHAR *AddressOfProcessExe) {
  DWORD ExitCode;

  //
  // We have 2 paths * 2 (because of unicode) + one extra path for process ID
  // and process name
  //
  WCHAR *TargetCommand = (WCHAR *)malloc(MaximumCommandSize);
  RtlZeroMemory(TargetCommand, MaximumCommandSize);
  BOOLEAN Result = TRUE;
  swprintf_s(TargetCommand, MaximumCommandSize / 2,
             L" pid \"%d\" ppath \"%ws\" fpath \"%ws\" ",
             ProcessId, // PathFindFileNameW(AddressOfProcessExe)
             AddressOfProcessExe, AccessedFileName);

  STARTUPINFO info = {sizeof(info)};
  PROCESS_INFORMATION processInfo;
  if (CreateProcessW(GUI_APP_NAME, TargetCommand, NULL, NULL, TRUE, 0, NULL,
                     NULL, &info, &processInfo)) {
    WaitForSingleObject(processInfo.hProcess, INFINITE);

    if (GetExitCodeProcess(processInfo.hProcess, &ExitCode) == FALSE) {
      Result = TRUE;
    } else if (ExitCode == STILL_ACTIVE) {

      Result = TRUE;
    } else {
      if (ExitCode == 2) {
        Result = FALSE;
      } else {
        Result = TRUE;
      }
    }

    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);
  } else {
    printf("err in opening process, %x \n", GetLastError());
  }

  free(TargetCommand);

  return Result;
}
VOID DisplayImmediateBlockMessageBox() {

  BOOLEAN Result = TRUE;

  int msgboxID = MessageBox(NULL, (LPCWSTR)L"A possible ransomware blocked.",
                            (LPCWSTR)L"Anti Ransomware Alert",
                            MB_ICONINFORMATION | MB_OK | MB_DEFBUTTON1);
}

BOOLEAN GetFileAddressByProcessId(DWORD ProcessId, WCHAR *Filename) {

  HANDLE processHandle = NULL;
  HANDLE ProcessHandle = OpenProcess(
      PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId);

  if (ProcessHandle != NULL) {
    if (GetModuleFileNameEx(ProcessHandle, NULL, Filename, MAX_PATH) == 0) {

      //
      // err, Failed to get module filename
      //
      return FALSE;

    } else {
      return TRUE;
    }
    CloseHandle(ProcessHandle);
  } else {
    //
    // err, Failed to open process
    //
    return FALSE;
  }
}

BOOLEAN IsExplorerProcess(DWORD ProcessId) {

  HANDLE processHandle = NULL;
  WCHAR filename[MAX_PATH];
  WCHAR windir[MAX_PATH];
  WCHAR explorerdir[MAX_PATH];

  processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                              FALSE, ProcessId);
  if (processHandle != NULL) {
    if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH) == 0) {
      // printf("Failed to get module filename.\n");
      return FALSE;

    } else {
      GetWindowsDirectory(windir, MAX_PATH);
      swprintf_s(explorerdir, L"%s\\explorer.exe", windir);
      // printf("Module filename is: %ws\n", filename);
      if (wcscmp(explorerdir, filename) == 0) {
        return TRUE;
      } else {
        return FALSE;
      }
    }
    CloseHandle(processHandle);
  } else {
    // printf("Failed to open process.");
    return FALSE;
  }
  return FALSE;
}

void HandleMessage(HANDLE CommunicationPort, const BYTE *buffer) {

  TCHAR AddressOfProcessFilename[MAX_PATH] = {0};

  BOOL IsInWhiteList = FALSE;

  auto msg = (PANTI_RANSOMWARE_PORT_MESSAGE)buffer;
  std::wstring filename(msg->FileName, msg->FileNameLength);

  if (msg->OperationType == OPERATION_WRITE_FILE) {
    printf("File changed : %ws\n", filename.c_str());
  } else if (msg->OperationType == OPERATION_DELETE_FILE_SET_INFORMATION) {
    printf("File deleted (Set Information) : %ws\n", filename.c_str());
  } else if (msg->OperationType == OPERATION_DELETE_FILE_ON_CLOSE) {
    printf("File deleted (Delete on Close) : %ws\n", filename.c_str());
  } else {
    printf("Invalid message received.\n");
  }

  if (msg->ShouldBeSuspended == TRUE) {

    //
    // Check if the process is in white list
    //
    for (auto item : ProcessTrace) {

      if (msg->ProcessId == item.ProcessId) {
        IsInWhiteList = TRUE;
        break;
      }
    }

    if (!IsInWhiteList) {

      BOOLEAN IsExplorer = IsExplorerProcess((DWORD)msg->ProcessId);

      if (!IsExplorer) {
        //
        // Get the detail of the process
        //
        GetFileAddressByProcessId((UINT32)msg->ProcessId,
                                  AddressOfProcessFilename);

        Suspend((DWORD)msg->ProcessId, true);
      }

      if (!IsExplorer && DisplayBlockMessageBox(msg->ProcessId, msg->FileName,
                                                AddressOfProcessFilename)) {

        //
        // User pressed 'yes', no need to continue the threads
        //
      } else {

        //
        // User pressed 'no', we should resume the ransomware
        //
        if (!IsExplorer) {
          Suspend((DWORD)msg->ProcessId, false);
        }

        //
        // Send whitelist request to the kernel
        //
        RegisterProcessToWhitelist(CommunicationPort, (UINT32)msg->ProcessId);

        //
        // Add it to the white list
        //
        ANTI_RANSOMWARE_PROCESS_TRACE CurrentProcess = {0};
        CurrentProcess.ProcessId = msg->ProcessId;
        CurrentProcess.IsOnTheWhiteList = TRUE;

        //
        // Add it to the list of trace process
        //
        ProcessTrace.push_back(CurrentProcess);
      }
    }
  }

  if (msg->ImmediateActions) {

    //
    // We will suspend all of the threads without any notice
    //

    Suspend((DWORD)msg->ProcessId, true);
    DisplayImmediateBlockMessageBox();
  }
}

BOOLEAN SendIoctlRequest(HANDLE CommunicationPort, UINT32 IoctlCode,
                         UINT64 OptionalParam1, UINT64 OptionalParam2,
                         UINT64 OptionalParam3, UINT64 OptionalParam4) {

  DWORD ReturnedLen;
  HRESULT hRes;

  //
  // prepare the request
  //
  ANTI_RANSOMWARE_FLT_IOCTL_REQUEST Request = {0};

  Request.IoctlRequest = IoctlCode;

  Request.OptionalParam1 = OptionalParam1;
  Request.OptionalParam2 = OptionalParam2;
  Request.OptionalParam3 = OptionalParam3;
  Request.OptionalParam4 = OptionalParam4;

  //
  // Send the request to the kernel handler, we use the same location for
  // for both sent and received buffers
  //
  hRes = FilterSendMessage(
      CommunicationPort, &Request, sizeof(ANTI_RANSOMWARE_FLT_IOCTL_REQUEST),
      &Request, sizeof(ANTI_RANSOMWARE_FLT_IOCTL_REQUEST), &ReturnedLen);

  if (IS_ERROR(hRes)) {
    return FALSE;
  }

  return TRUE;
}

BOOLEAN RegisterProcessToWhitelist(HANDLE CommunicationPort, UINT32 ProcessId) {

  //
  // Send the request to send it as an IOCTL request
  //
  return SendIoctlRequest(CommunicationPort, IOCTL_REQUEST_PROCESS_ID_WHITELIST,
                          ProcessId, NULL, NULL, NULL);
}

#define INF_FILE_NAME "SystemMon.inf"

BOOLEAN
SetupInfoFileName(_Inout_updates_bytes_all_(BufferLength) PCHAR TestLocation,
                  ULONG BufferLength) {

  HANDLE fileHandle;
  DWORD driverLocLen = 0;
  HMODULE ProcHandle = GetModuleHandle(NULL);
  char *Pos;

  //
  // Get the current directory.
  //
  GetModuleFileNameA(ProcHandle, TestLocation, BufferLength);

  Pos = strrchr(TestLocation, '\\');
  if (Pos != NULL) {
    //
    // this will put the null terminator here. you can also copy to
    // another string if you want, we can also use PathCchRemoveFileSpec
    //
    *Pos = '\0';
  }

  //
  // Setup path name to driver file
  //
  if (FAILED(StringCbCatA(TestLocation, BufferLength, "\\" INF_FILE_NAME))) {
    return FALSE;
  }

  //
  // Insure driver file is in the specified directory
  //
  if ((fileHandle = CreateFileA(TestLocation, GENERIC_READ, 0, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) ==
      INVALID_HANDLE_VALUE) {

    printf("%s.exe is not loaded.\n", INF_FILE_NAME);

    //
    // Indicate failure
    //
    return FALSE;
  }

  //
  // Close open file handle
  //
  if (fileHandle) {

    CloseHandle(fileHandle);
  }

  //
  // Indicate success
  //
  return TRUE;
}

DWORD WINAPI CheckForBackupDeletionProcesss(LPVOID lpParam) {

  for (;;) {

    //
    // Check and delete
    //
    CheckAndDeleteBackup();

    //
    // Check each one hours
    //
    Sleep(3600 * 1000);
  }

  return 0;
}
void DisplayVolumePaths(__in PWCHAR VolumeName, wchar_t *PathToSave) {

  DWORD CharCount = MAX_PATH + 1;
  PWCHAR NameIdx = NULL;
  BOOL Success = FALSE;

  for (;;) {

    //
    //  Allocate a buffer to hold the paths
    //

    //
    //  Obtain all of the paths for this volume
    //
    Success = GetVolumePathNamesForVolumeNameW(VolumeName, PathToSave,
                                               CharCount, &CharCount);

    if (Success) {
      break;
    }

    if (GetLastError() != ERROR_MORE_DATA) {
      break;
    }
  }

  if (Success) {

    //
    //  Display the various paths
    //
    for (NameIdx = PathToSave; NameIdx[0] != L'\0';
         NameIdx += wcslen(NameIdx) + 1) {
      // wprintf(L"  %s", NameIdx);
    }
    // wprintf(L"\n");
  }
}

wchar_t *GetNameOfPrimaryDevice(wchar_t *DeviceName) {

  DWORD CharCount = 0;
  DWORD Error = ERROR_SUCCESS;
  HANDLE FindHandle = INVALID_HANDLE_VALUE;
  BOOL Found = FALSE;
  size_t Index = 0;
  BOOL Success = FALSE;
  WCHAR VolumeName[MAX_PATH] = {0};
  WCHAR VolumeNameOfDriver[MAX_PATH] = {0};

  //
  // Get name of primary drive
  //
  // Get system folder
  //
  WCHAR WinPath[MAX_PATH] = {0};

  GetSystemWindowsDirectoryW(WinPath, sizeof(WinPath));
  ZeroMemory(WinPath + 3, 40);

  // wprintf(L"Windows Path : %s\n", WinPath);

  //
  //  Enumerate all volumes in the system
  //
  FindHandle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));

  if (FindHandle == INVALID_HANDLE_VALUE) {
    Error = GetLastError();
    wprintf(L"FindFirstVolumeW failed with error code %d\n", Error);
    return NULL;
  }

  for (;;) {

    //
    //  Skip the \\?\ prefix and remove the trailing backslash
    //
    Index = wcslen(VolumeName) - 1;

    if (VolumeName[0] != L'\\' || VolumeName[1] != L'\\' ||
        VolumeName[2] != L'?' || VolumeName[3] != L'\\' ||
        VolumeName[Index] != L'\\') {
      Error = ERROR_BAD_PATHNAME;
      wprintf(L"FindFirstVolumeW/FindNextVolumeW returned a bad path: %s\n",
              VolumeName);
      break;
    }

    //
    // QueryDosDeviceW does not allow a trailing backslash,
    // so temporarily remove it
    //
    VolumeName[Index] = L'\0';

    CharCount = QueryDosDeviceW(&VolumeName[4], DeviceName, MAX_PATH);

    VolumeName[Index] = L'\\';

    if (CharCount == 0) {
      Error = GetLastError();
      wprintf(L"QueryDosDeviceW failed with error code %d\n", Error);
      break;
    }

    // wprintf(L"\nFound a device:\n %s", DeviceName);
    // wprintf(L"\nVolume name: %s", VolumeName);
    // wprintf(L"\nPaths:");
    DisplayVolumePaths(VolumeName, VolumeNameOfDriver);

    //
    // Check if the new address is equal to the address
    //
    if (wcscmp(VolumeNameOfDriver, WinPath) == 0) {

      return DeviceName;
    }

    //
    //  Move on to the next volume
    //
    Success = FindNextVolumeW(FindHandle, VolumeName, ARRAYSIZE(VolumeName));

    if (!Success) {
      Error = GetLastError();

      if (Error != ERROR_NO_MORE_FILES) {
        wprintf(L"FindNextVolumeW failed with error code %d\n", Error);
        break;
      }

      //
      //  Finished iterating
      //  through all the volumes
      //
      Error = ERROR_SUCCESS;
      break;
    }
  }

  FindVolumeClose(FindHandle);
  FindHandle = INVALID_HANDLE_VALUE;

  return NULL;
}

int main() {

  WCHAR DeviceName[MAX_PATH] = {0};
  BYTE buffer[1 << 12]; // 4 KB
  auto message = (FILTER_MESSAGE_HEADER *)buffer;
  UINT32 ExtensionsBufferSize =
      sizeof(UINT32) + SIZE_OF_EXTENSION_BUFFER; /* We add UINT32 Because, it
                                                    will be the IOCTL */
  wchar_t *splittedItem;
  wchar_t *next_token = NULL;
  UINT32 Counter = 0;
  HANDLE hPort;
  HRESULT hRes;
  DWORD ReturnedLen;

  CHAR InfFileLocation[MAX_PATH] = {0};
  CHAR InfRegisterCommand[MAX_PATH + 50] = {
      0}; // add infdefaultinstall.exe at the begining of it

  //
  // Set-up path
  //
  if (!SetupInfoFileName(InfFileLocation, sizeof(InfFileLocation))) {

    //
    // Test process not found
    //
    return 1;
  }

  //
  // Concat the buffer with command
  //
  sprintf_s(InfRegisterCommand, "infdefaultinstall.exe %s", InfFileLocation);

  //
  // Install the driver
  //
  system(InfRegisterCommand);

  system("fltmc.exe load SystemMon");

  //
  // Create file delete checker thread
  //
  CreateThread(NULL,                           // default security attributes
               0,                              // use default stack size
               CheckForBackupDeletionProcesss, // thread function name
               NULL,                           // argument to thread function
               0,                              // use default creation flags
               NULL);                          // returns the thread identifier

  //
  // Allocate and zero-out memory
  //
  UINT64 AddressOfExtensionsBuffer = (UINT64)malloc(ExtensionsBufferSize);
  RtlZeroMemory((PVOID)AddressOfExtensionsBuffer, ExtensionsBufferSize);

  wchar_t AllExtensions[] =
      L".yuv,.ycbcra,.xis,.x3f,.x11,.wpd,.tex,.sxg,.stx,.st8,.st5,.srw,.srf,."
      "sr2,.sqlitedb,.sqlite3,.sqlite,.sdf,.sda,.sd0,.s3db,.rwz,.rwl,.rdb,."
      "rat,.raf,.qby,.qbx,.qbw,.qbr,.qba,.py,.exe,.psafe3,.plc,.plus_muhd,.pdd,"
      "."
      "p7c,.p7b,.oth,.orf,.odm,.odf,.nyf,.nxl,.nx2,.nwb,.ns4,.ns3,.ns2,.nrw,."
      "nop,."
      "nk2,.nef,.ndd,.myd,.mrw,.moneywell,.mny,.mmw,.mfw,.mef,.mdc,.lua,."
      "kpdx,."
      "kdc,.kdbx,.kc2,.jpe,.incpas,.iiq,.ibz,.ibank,.hbk,.gry,.grey,.gray,."
      "fhd,"
      ".fh,.ffd,.exf,.erf,.erbsql,.eml,.dxg,.drf,.dng,.dgc,.des,.der,.ddrw,."
      "ddoc,.dcs,.dc2,.db_journal,.csl,.csh,.crw,.craw,.cib,.ce2,.ce1,.cdrw,."
      "cdr6,.cdr5,.cdr4,.cdr3,.bpw,.bgt,.bdb,.bay,.bank,.backupdb,.backup,."
      "back,.awg,.apj,.ait,.agdl,.ads,.adb,.acr,.ach,.accdt,.accdr,.accde,."
      "ab4,"
      ".3pr,.3fr,.vmxf,.vmsd,.vhdx,.vhd,.vbox,.stm,.st7,.rvt,.qcow,.qed,.pif,"
      "."
      "pdb,.pab,.ost,.ogg,.nvram,.ndf,.m4p,.m2ts,.log,.hpp,.hdd,.groups,."
      "flvv,."
      "edb,.dit,.dat,.cmt,.bin,.aiff,.xlk,.wad,.tlg,.st6,.st4,.say,.sas7bdat,"
      "."
      "qbm,.qbb,.ptx,.pfx,.pef,.pat,.oil,.odc,.nsh,.nsg,.nsf,.nsd,.nd,.mos,."
      "indd,.iif,.fpx,.fff,.fdb,.dtd,.design,.ddd,.dcr,.dac,.cr2,.cdx,.cdf,."
      "blend,.bkp,.al,.adp,.act,.xlr,.xlam,.xla,.wps,.tga,.rw2,.r3d,."
      "pspimage,."
      "ps,.pct,.pcd,.m4v,.fxg,.flac,.eps,.dxb,.drw,.dot,.db3,.cpi,.cls,.cdr,."
      "arw,.ai,.aac,.thm,.srt,.save,.safe,.rm,.pwm,.pages,.obj,.mlb,.md,.mbx,"
      "."
      "lit,.laccdb,.kwm,.idx,.html,.flf,.dxf,.dwg,.dds,.csv,.css,.config,."
      "cfg,."
      "cer,.asx,.aspx,.aoi,.accdb,.7zip,.1cd,.xls,.wab,.rtf,.prf,.ppt,.oab,."
      "msg,.mapimail,.jnt,.doc,.dbx,.contact,.n64,.m4a,.m4u,.m3u,.mid,.wma,."
      "flv,.3g2,.mkv,.3gp,.mp4,.mov,.avi,.asf,.mpeg,.vob,.mpg,.wmv,.fla,.swf,"
      "."
      "wav,.mp3,.qcow2,.vdi,.vmdk,.vmx,.wallet,.upk,.sav,.re4,.ltx,.litesql,."
      "litemod,.lbf,.iwi,.forge,.das,.d3dbsp,.bsa,.bik,.asset,.apk,.gpg,.aes,"
      "."
      "arc,.paq,.tar.bz2,.tbk,.bak,.tar,.tgz,.gz,.7z,.rar,.zip,.djv,.djvu,."
      "svg,"
      ".bmp,.png,.gif,.raw,.cgm,.jpeg,.jpg,.tif,.tiff,.nef,.psd,.cmd,.bat,."
      "sh,."
      "class,.jar,.java,.rb,.asp,.cs,.brd,.sch,.dch,.dip,.pl,.vbs,.vb,.js,."
      "asm,"
      ".pas,.cpp,.php,.ldf,.mdf,.ibd,.myi,.myd,.frm,.odb,.dbf,.db,.mdb,.sql,."
      "sqlitedb,.sqlite3,.011,.010,.009,.008,.007,.006,.005,.004,.003,.002,."
      "001,.pst,.onetoc2,.asc,.lay6,.lay,.ms11,.sldm,.sldx,.ppsm,.ppsx,.ppam,"
      "."
      "docb,.mml,.sxm,.otg,.odg,.uop,.potx,.potm,.pptx,.pptm,.std,.sxd,.pot,."
      "pps,.sti,.sxi,.otp,.odp,.wb2,.123,.wks,.wk1,.xltx,.xltm,.xlsx,.xlsm,."
      "xlsb,.slk,.xlw,.xlt,.xlm,.xlc,.dif,.stc,.sxc,.ots,.ods,.hwp,.602,."
      "dotm,."
      "dotx,.docm,.docx,.dot,.3dm,.max,.3ds,.xml,.txt,.csv,.uot,.rtf,.pdf,."
      "stw,"
      ".sxw,.ott,.odt,.doc,.pem,.p12,.csr,.crt,.key.sxw,.ott,.odt,.doc,.pem,."
      "p12,.csr,.crt,.key";

  // printf("Splitting string \"%ws\" into tokens:\n", AllExtensions);
  splittedItem = wcstok_s(AllExtensions, L",", &next_token);

  //
  // Add the ioctl code on top of the buffer
  //
  *(UINT32 *)AddressOfExtensionsBuffer = IOCTL_REGISTER_EXTENSIONS;

  while (splittedItem != NULL) {

    wchar_t *CurrentExtensionAddr =
        (wchar_t *)(AddressOfExtensionsBuffer + sizeof(UINT32) +
                    MAXIMUM_LENGTH_OF_EACH_EXTENSION * 2 * Counter);

    wcscpy_s(CurrentExtensionAddr, wcslen(splittedItem) + 1, splittedItem);

    Counter++;

    splittedItem = wcstok_s(NULL, L",", &next_token);
  }

  auto hr = ::FilterConnectCommunicationPort(L"\\SystemMonPort", 0,
                                             nullptr, 0, nullptr, &hPort);
  if (FAILED(hr)) {
    printf("Error connecting to port (HR=0x%08X)\n", hr);
    return 1;
  }

  //
  // Send the request to the kernel handler, we use the same location for
  // for both sent and received buffers
  //
  hRes = FilterSendMessage(hPort, (PVOID)AddressOfExtensionsBuffer,
                           ExtensionsBufferSize, NULL, 0, &ReturnedLen);

  if (IS_ERROR(hRes)) {
    return FALSE;
  }

  //
  // driver connected to the user process
  // now we set it as the critical process
  //
  if (EnableSeDebugPrivilege()) {
    SetProcessAsCritical();
  }

  //
  // Find the primary driver
  // ====================================================================================
  //

  //
  // We send it as the previously allocated buffer
  //
  wchar_t *PrimaryDisk = GetNameOfPrimaryDevice(DeviceName);

  //
  // Make it lower case
  //
  _wcslwr_s(PrimaryDisk, MAX_PATH);

  RtlZeroMemory((PVOID)AddressOfExtensionsBuffer, ExtensionsBufferSize);

  //
  // Set the IOCTL to the top of the buffer
  //
  *(UINT32 *)AddressOfExtensionsBuffer = IOCTL_SET_PRIMARY_DRIVE;

  RtlCopyMemory((wchar_t *)((UINT64)AddressOfExtensionsBuffer + sizeof(UINT32)),
                PrimaryDisk, MAX_PATH);

  // wprintf(L"The primary disk is : %s\n", PrimaryDisk);

  //
  // Send the request
  //
  hRes = FilterSendMessage(hPort, (PVOID)AddressOfExtensionsBuffer,
                           ExtensionsBufferSize, NULL, 0, &ReturnedLen);

  if (IS_ERROR(hRes)) {
    return FALSE;
  }

  // ====================================================================================

  for (;;) {
    hr = ::FilterGetMessage(hPort, message, sizeof(buffer), nullptr);
    if (FAILED(hr)) {
      printf("Error receiving message (0x%08X)\n", hr);
      break;
    }

    HandleMessage(hPort, buffer + sizeof(FILTER_MESSAGE_HEADER));
  }

  ::CloseHandle(hPort);

  return 0;
}
