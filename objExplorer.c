#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <sddl.h> 

#pragma comment(lib, "Advapi32.lib")


/*
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);       \
    (p)->RootDirectory = r;                        \
    (p)->Attributes = a;                           \
    (p)->ObjectName = n;                           \
    (p)->SecurityDescriptor = s;                   \
    (p)->SecurityQualityOfService = NULL;          \
}

typedef struct _UNICODE_STRING {
    USHORT Length;         // Length of the string in bytes (excluding null terminator)
    USHORT MaximumLength;  // Total size of the buffer in bytes
    PWSTR  Buffer;         // Pointer to the wide-character string
} UNICODE_STRING, *PUNICODE_STRING;

VOID RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
) {
    if (SourceString) {
        DestinationString->Length = (USHORT)wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
        DestinationString->Buffer = (PWSTR)SourceString;
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }
}

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
*/

VOID RtlInitUnicodeString(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
) {
    if (SourceString) {
        DestinationString->Length = (USHORT)wcslen(SourceString) * sizeof(WCHAR);
        DestinationString->MaximumLength = DestinationString->Length + sizeof(WCHAR);
        DestinationString->Buffer = (PWSTR)SourceString;
    } else {
        DestinationString->Length = 0;
        DestinationString->MaximumLength = 0;
        DestinationString->Buffer = NULL;
    }
}

typedef NTSTATUS (NTAPI *PFN_NtOpenDirectoryObject)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *pNtQueryDirectoryObject)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *NtOpenSection_t)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *NtOpenSymbolicLinkObject_t)(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *NtQuerySymbolicLinkObject_t)(
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength // Optional, can be NULL
);

typedef struct _OBJDIR_INFORMATION {
    UNICODE_STRING Name;       // Object name
    UNICODE_STRING TypeName;   // Type of object (e.g., "SymbolicLink", "Directory")
    BYTE Padding[8];           // Optional alignment padding
} OBJDIR_INFORMATION, *POBJDIR_INFORMATION;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS (NTAPI *NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG PageProtection
);

typedef NTSTATUS (NTAPI *NtOpenEvent_t)(
    PHANDLE            EventHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);


BOOL GetSecurityDescriptor(HANDLE hObject) {
    
    HMODULE hAdvapi32 = LoadLibrary("Advapi32.dll");
    if (!hAdvapi32) {
        printf("Failed to load Advapi32.dll!\n");
        return FALSE;
    }

    typedef BOOL (WINAPI *pIsValidSecurityDescriptor)(PSECURITY_DESCRIPTOR);
    pIsValidSecurityDescriptor IsValidSD = (pIsValidSecurityDescriptor)GetProcAddress(hAdvapi32, "IsValidSecurityDescriptor");

    if (!IsValidSD) {
     printf("Failed to retrieve IsValidSecurityDescriptor function!\n");
     FreeLibrary(hAdvapi32);
     return FALSE;
    }

    typedef NTSTATUS (NTAPI *pZwQuerySecurityObject)(
        HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG
    );

    //setting dll manually
    HMODULE hNtDll = LoadLibrary("ntdll.dll");
    pZwQuerySecurityObject ZwQuerySecurityObject = (pZwQuerySecurityObject)GetProcAddress(hNtDll, "ZwQuerySecurityObject");

    ULONG sdSize = 0;
    //this also sets the size for the psd alloc
    NTSTATUS status = ZwQuerySecurityObject(hObject, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, NULL, sdSize, &sdSize);

    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)malloc(sdSize);
    if (!pSD) {
        printf("Memory allocation failed!\n");
        return FALSE;
    }

    status = ZwQuerySecurityObject(hObject, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, pSD, sdSize, &sdSize);

    if (!IsValidSD(pSD)) {
       // printf("Invalid security descriptor!\n");
     return FALSE;
    }

    PSID ownerSID = NULL;
    PSID oGroup;
    PACL dasl;
    BOOL ownerDefaulted;
    BOOL ownerDefaultedGroup;
    BOOL ownerDefaultedDasl;
    BOOL daslPresent;
    //getting owner
    if (!GetSecurityDescriptorOwner(pSD, &ownerSID, &ownerDefaulted)) {
      printf("error getting owner SID\n");
      return FALSE;
    }
    // getting group
    if (!GetSecurityDescriptorGroup(pSD, &oGroup, &ownerDefaultedGroup)){
        printf("error getting Object group\n");
        return FALSE;
    }
    //getting dacl
    if (!GetSecurityDescriptorDacl(pSD, &daslPresent, &dasl, &ownerDefaultedDasl)) {
        printf("error getting DACL\n");
        return FALSE;
    } else {
      if (daslPresent == FALSE) {
          printf("No group permissions set\n");
      }
    }

    LPSTR daclOut;
    if (ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, 1, DACL_SECURITY_INFORMATION, &daclOut, NULL)) {
        printf("\x1b[92m[+]\x1b[0m DACL: %s\n", daclOut);
    }

//ConvertStringSecurityDescriptorToSecurityDescriptor found this use later to set a descriptor?

    LPSTR sidstring;
    if (ConvertSidToStringSid(ownerSID, &sidstring)) {
        printf("\x1b[92m[+]\x1b[0m SID: %s\n", sidstring);
    } else {
      printf("error geeting SID\n");
      return FALSE;
    }
//SE_OBJECT_TYPE sObj;
//SECURITY_INFORMATION sInfo;
//if (GetSecurityInfo(hObject, sObj, sInfo, &ownerSID, &oGroup,  ))


    char name[256];
    char domain[256];
    DWORD nameLen = sizeof(name);
    DWORD domainLen = sizeof(domain);
    SID_NAME_USE sidType;

    PSID psdString = NULL;
    ConvertStringSidToSidA(sidstring, &psdString);
    if (!LookupAccountSidA(NULL, psdString, name, &nameLen, domain, &domainLen, &sidType)) {
        printf("Error looking up SID name and domain %lu\n", GetLastError());
    }

    printf("\x1b[92m[+]\x1b[0m NT %s\\%s\\\n", name, domain);

    return TRUE;
    FreeLibrary(hAdvapi32);
    FreeLibrary(hNtDll);
}

//#define OBJ_CASE_INSENSITIVE 0x00000040

void PrintObjectAttributes(POBJECT_ATTRIBUTES objAttr) {
    printf("OBJECT_ATTRIBUTES Dump:\n");
    printf("  Length: %lu\n", objAttr->Length);
    printf("  RootDirectory: 0x%p\n", objAttr->RootDirectory);

    if (objAttr->ObjectName) {
        printf("  ObjectName: Length=%hu, MaxLength=%hu, Buffer=%ws\n",
               objAttr->ObjectName->Length,
               objAttr->ObjectName->MaximumLength,
               objAttr->ObjectName->Buffer);
    } else {
        printf("  ObjectName: (null)\n");
    }

    printf("  Attributes: 0x%08lx\n", objAttr->Attributes);

    if (objAttr->SecurityDescriptor) {
        printf("  SecurityDescriptor: 0x%p\n", objAttr->SecurityDescriptor);
        // You can use GetSecurityDescriptorOwner or similar to extract more details
    } else {
        printf("  SecurityDescriptor: (null)\n");
    }

    if (objAttr->SecurityQualityOfService) {
        printf("  SecurityQualityOfService: 0x%p\n", objAttr->SecurityQualityOfService);
        // Optionally print fields inside SECURITY_QUALITY_OF_SERVICE
    } else {
        printf("  SecurityQualityOfService: (null)\n");
    }
}

// Setup
HANDLE hNtdll;
NtOpenSection_t NtOpenSection;
NtOpenSymbolicLinkObject_t NtOpenSymbolicLinkObject;
NtQuerySymbolicLinkObject_t NtQuerySymbolicLinkObject;
PFN_NtOpenDirectoryObject NtOpenDirectoryObject;
NtOpenEvent_t NtOpenEvent;

BOOL setup() {

    hNtdll = GetModuleHandle("ntdll.dll");

    NtOpenSection = (NtOpenSection_t)GetProcAddress(hNtdll, "NtOpenSection");
    if (!NtOpenSection) return 1;

    NtOpenSymbolicLinkObject = (NtOpenSymbolicLinkObject_t)GetProcAddress(hNtdll, "NtOpenSymbolicLinkObject");
    if (!NtOpenSymbolicLinkObject) return 1;

    NtQuerySymbolicLinkObject = (NtQuerySymbolicLinkObject_t)GetProcAddress(hNtdll, "NtQuerySymbolicLinkObject");
    if (!NtQuerySymbolicLinkObject) return 1;

    NtOpenDirectoryObject = (PFN_NtOpenDirectoryObject)GetProcAddress(hNtdll, "NtOpenDirectoryObject");
    if (!NtOpenDirectoryObject) return 1;

    NtOpenEvent = (NtOpenEvent_t)GetProcAddress(hNtdll, "NtOpenEvent");
    if (!NtOpenEvent) return 1;

    return 0;
}

int wmain(int argc, wchar_t *argv[]) {

HANDLE hDir;
UNICODE_STRING dirName;
OBJECT_ATTRIBUTES oa;
ULONG ctx = 0, retLen = 0;
BYTE buffer[0x15000];

    setup();

RtlInitUnicodeString(&dirName, argv[1]);
InitializeObjectAttributes(&oa, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

NTSTATUS status = NtOpenDirectoryObject(&hDir, 0x0001, &oa);

// NtQueryDirectoryObject
pNtQueryDirectoryObject NtQueryDirectoryObject = (pNtQueryDirectoryObject)GetProcAddress(hNtdll, "NtQueryDirectoryObject");

if (NtQueryDirectoryObject) {
        status = NtQueryDirectoryObject(
            hDir,
            buffer,
            sizeof(buffer),
            FALSE,     
            TRUE,       
            &ctx,
            &retLen
        );
        if (NT_SUCCESS(status)) {

            int offset = 0;
            UNICODE_STRING target;

            printf("%lu\n", retLen);

            for (int i=0; i < retLen; i++) {
            OBJDIR_INFORMATION* entry = (OBJDIR_INFORMATION*)buffer + offset;

            if (wcscmp(entry[i].Name.Buffer, L"") == 0) break;

            wprintf(L"%ws\n", entry[i].Name.Buffer);

            // File walker
            if (argv[2]) {

            if (wcscmp(entry[i].Name.Buffer, argv[2]) == 0) {

            printf("\x1b[2J\x1b[H");

            printf("Starting walker-object-ranger");
            for (int i=0; i < 3; i++) {
                printf(".");
                Sleep(300);
            }
            printf("\n");

            
            while (1) {
                
                wprintf(L"walker-object-ranger@%ws >> ", entry[i].Name.Buffer);

                wchar_t lineBuff[100];
                fgetws(lineBuff, 99, stdin);
                lineBuff[wcscspn(lineBuff, L"\n")] = L'\0';

                if (wcscmp(lineBuff, L"walk") == 0) {

                    wchar_t pathBuff[150];
                    puts("Directory path??");
                    fgetws(pathBuff, sizeof(pathBuff) - 1, stdin);

                    pathBuff[wcscspn(pathBuff, L"\n")] = L'\0';

                    wchar_t findBuff[1024];
                    swprintf(findBuff, sizeof(findBuff), L"\\\\?\\GLOBALROOT\\Device\\%ws\\%ws\\*", entry[i].Name.Buffer, pathBuff);

                    //printf("%ws\n", findBuff);
                    WIN32_FIND_DATAW findData;

                    HANDLE hFind = FindFirstFileW(findBuff, &findData);

                    if (hFind == INVALID_HANDLE_VALUE) {
                    printf("FindFirstFile failed. Error: %lu\n", GetLastError());
                    } else {
                
                    wprintf(L"[+] %s\n", findData.cFileName);

                    while (FindNextFileW(hFind, &findData)) {

                        if (wcscmp(findData.cFileName, ".") == 0 || wcscmp(findData.cFileName, "..") == 0) {
                        continue;
                        } else {
                           ULONGLONG size = ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;

                            if (size == 0) {
                            wprintf(L"[+] %s - [Directory]\n", findData.cFileName);
                            } else {
                             wprintf(L"[+] %s - [%lu]\n", findData.cFileName, size);
                            }
                        }

                    }

                }

            }

                if (wcscmp(lineBuff, L"list") == 0) {

                    wchar_t findBuff[1024];
                    swprintf(findBuff, sizeof(findBuff), L"\\\\?\\GLOBALROOT\\Device\\%ws\\*", entry[i].Name.Buffer);

                    WIN32_FIND_DATAW findData;

                    HANDLE hFind = FindFirstFileW(findBuff, &findData);

                    if (hFind == INVALID_HANDLE_VALUE) {
                    printf("FindFirstFile failed. Error: %lu\n", GetLastError());
                    return 0;
                    } else {
                
                    wprintf(L"%s\n", findData.cFileName);

                    while (FindNextFileW(hFind, &findData)) {
                            ULONGLONG size = ((ULONGLONG)findData.nFileSizeHigh << 32) | findData.nFileSizeLow;

                            if (size == 0) {
                            wprintf(L"[+] %s - [Directory]\n", findData.cFileName);
                            } else {
                             wprintf(L"[+] %s - [%lu]\n", findData.cFileName, size);
                            }
                    }

                }

            }

            else if ((wcscmp(lineBuff, L"read") == 0)) {

            HANDLE hFile;
            DWORD bytesRead;

            wchar_t pathBuff[150];
            puts("path?");
            fgetws(pathBuff, sizeof(pathBuff) - 1, stdin);

            pathBuff[wcscspn(pathBuff, L"\n")] = L'\0';

            wchar_t finalBuff[1024];
            swprintf(finalBuff, sizeof(finalBuff), L"\\\\?\\GLOBALROOT\\Device\\%ws\\%ws", entry[i].Name.Buffer, pathBuff);

            hFile = CreateFileW(
             finalBuff,
             GENERIC_READ,
             FILE_SHARE_READ,
             NULL,
             OPEN_EXISTING,
             FILE_ATTRIBUTE_NORMAL,
             NULL
             );

             WIN32_FILE_ATTRIBUTE_DATA fad;
             ULONGLONG size = 0;
            if (GetFileAttributesExW(finalBuff, GetFileExInfoStandard, &fad)) {
              size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
            }

            printf("%lu\n", size);
            char* buffer = malloc(size);

            if (hFile == INVALID_HANDLE_VALUE) {
               printf("error %lu\n", GetLastError());
               return 1;
            }

             if (!ReadFile(hFile, buffer, size, &bytesRead, NULL)) {
                printf("Error reading\n");
                return 1;
            }

            buffer[size] = '\0';

            printf("%s\n", buffer);

        }

        else if(wcscmp(lineBuff, L"copy") == 0) {

            HANDLE hFile;
            DWORD bytesRead;

            wchar_t pathBuff[150];
            puts("path?");
            fgetws(pathBuff, sizeof(pathBuff) - 1, stdin);

            pathBuff[wcscspn(pathBuff, L"\n")] = L'\0';

            wchar_t finalBuff[1024];
            swprintf(finalBuff, sizeof(finalBuff), L"\\\\?\\GLOBALROOT\\Device\\%ws\\%ws", entry[i].Name.Buffer, pathBuff);

            hFile = CreateFileW(
             finalBuff,
             GENERIC_READ,
             FILE_SHARE_READ,
             NULL,
             OPEN_EXISTING,
             FILE_ATTRIBUTE_NORMAL,
             NULL
             );

             WIN32_FILE_ATTRIBUTE_DATA fad;
             ULONGLONG size = 0;
            if (GetFileAttributesExW(finalBuff, GetFileExInfoStandard, &fad)) {
              size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
            }

            printf("%lu\n", size);
            char* buffer = malloc(size);

            if (hFile == INVALID_HANDLE_VALUE) {
               printf("error %lu\n", GetLastError());
               return 1;
            }

             if (!ReadFile(hFile, buffer, size, &bytesRead, NULL)) {
                printf("Error reading\n");
                return 1;
            }

            buffer[size] = '\0';

            // writing

            wchar_t outBuff[150];
            puts("outfile name??");
            fgetws(outBuff, sizeof(outBuff) - 1, stdin);

            outBuff[wcscspn(outBuff, L"\n")] = L'\0';

            
            HANDLE outFile = CreateFileW(
             outBuff,
             GENERIC_WRITE,
             FILE_SHARE_READ,
             NULL,
             CREATE_ALWAYS,
             FILE_ATTRIBUTE_NORMAL,
             NULL
             );

             if (!outFile) {
                printf("Error %lu\n", GetLastError());
                return 0;
             }

            if (!WriteFile(outFile, buffer, size, NULL, NULL)) {
                puts("Error");
                return 1;
            }

            //return 0;

        }

         else if ((wcscmp(lineBuff, L"exit") == 0)) { 
            puts("see ya!");
            return 0;
         }

        }
        }
}

            if (wcscmp(argv[1], L"\\Global??") == 0) {
            
            UNICODE_STRING sectionName;
            OBJECT_ATTRIBUTES objAttr;
            HANDLE hSection;

            wchar_t fullPath[256];
            swprintf(fullPath, 256, L"\\Global??\\%s", entry[i].Name.Buffer);
            RtlInitUnicodeString(&sectionName, fullPath);
            InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

            NTSTATUS status = NtOpenSymbolicLinkObject(&hSection, GENERIC_READ, &objAttr);

           // NtQuerySymbolicLinkObject(hSection, &target, NULL);
            
            //wprintf(L"Target: %s\n", target);

            GetSecurityDescriptor(hSection);
            }

            if (wcscmp(argv[1], L"\\KnownDlls") == 0) {
                UNICODE_STRING sectionName;
                OBJECT_ATTRIBUTES objAttr;
                HANDLE hSection;

                wchar_t fullPath[256];
                swprintf(fullPath, 256, L"\\KnownDlls\\%s", entry[i].Name.Buffer);
                RtlInitUnicodeString(&sectionName, fullPath);
                InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

                NTSTATUS status = NtOpenSection(&hSection, GENERIC_READ, &objAttr);
                

            }
            

            if (offset % 2) { 
            puts("++++++++++++++++++++++++++++++++\n");
            }

            offset++;
            }
        } 
        
        else if (wcscmp(argv[1], L"-s") == 0) {
                
                UNICODE_STRING sectionName;
                OBJECT_ATTRIBUTES objAttr;
                HANDLE hSection;

                wchar_t fullPath[256];
                swprintf(fullPath, 256, L"\\\\?\\GLOBALROOT\\%ws", argv[2]);
                RtlInitUnicodeString(&sectionName, fullPath);
                InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

                wprintf(L"%ws\n", fullPath);

                NTSTATUS status1 = NtOpenSection(&hSection, GENERIC_READ, &objAttr);
                
                if (!NT_SUCCESS(status1)) {
                printf("Error %lu\n", status1);
                return 1;
                }


                NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapViewOfSection");

                BYTE* baseAddress2 = NULL;
                SIZE_T viewSize2 = 0;
               status1 = NtMapViewOfSection(hSection, GetCurrentProcess(), &baseAddress2, 0, 0, NULL, &viewSize2, ViewUnmap, 0, PAGE_READONLY);

               if (!NT_SUCCESS(status1)) {
                printf("Error 2 %lu\n", status1);
                return 1;
            }
                for (int i=0; i < 10; i++) {
                    printf("%02X ", baseAddress2[i]);
                }
                
    }

    else if (wcscmp(argv[1], L"event") == 0) {

                UNICODE_STRING sectionName;
                OBJECT_ATTRIBUTES objAttr;
                HANDLE hEvent;

                wchar_t fullPath[256];
                swprintf(fullPath, 256, L"\\\\?\\GLOBALROOT\\%ws", argv[2]);
                RtlInitUnicodeString(&sectionName, fullPath);
                InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

                //wprintf(L"%ws\n", fullPath);

                NTSTATUS status = NtOpenEvent(&hEvent, 0x0001, &objAttr);

                printf("EVENT: %ws - Valid\n\n", objAttr.ObjectName->Buffer);

                PrintObjectAttributes(&objAttr);
    
                return 0;
    }

    else if (wcscmp(argv[1], L"help") == 0) {
        puts("[+] [Directory] ex: \\KnownDlls - Read object directory\n[+] [Directory] [shadow copy] - Read HarddiskVolumeShadowCopy\n[+] [-s] [Section] - Read shared section from \\BaseNamedObjects\n");
    }

    //printf("\n");
    return 0;
}

}
