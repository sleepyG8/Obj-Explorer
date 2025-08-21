#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <sddl.h> 

#pragma comment(lib, "Advapi32.lib")

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

    LPSTR sidstring;
    if (ConvertSidToStringSid(ownerSID, &sidstring)) {
        printf("\x1b[92m[+]\x1b[0m SID: %s\n", sidstring);
    } else {
      printf("error geeting SID\n");
      return FALSE;
    }

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

int wmain(int argc, wchar_t *argv[]) {
  
HANDLE hDir;
UNICODE_STRING dirName;
OBJECT_ATTRIBUTES oa;
ULONG ctx = 0, retLen = 0;
BYTE buffer[0x2000];

RtlInitUnicodeString(&dirName, argv[1]);
InitializeObjectAttributes(&oa, &dirName, OBJ_CASE_INSENSITIVE, NULL, NULL);

HANDLE hNtdll = GetModuleHandle("ntdll.dll");

PFN_NtOpenDirectoryObject NtOpenDirectoryObject = (PFN_NtOpenDirectoryObject)GetProcAddress(hNtdll, "NtOpenDirectoryObject");

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

            NtOpenSection_t NtOpenSection = (NtOpenSection_t)GetProcAddress(hNtdll, "NtOpenSection");
            if (!NtOpenSection) return 1;

            NtOpenSymbolicLinkObject_t NtOpenSymbolicLinkObject = (NtOpenSymbolicLinkObject_t)GetProcAddress(hNtdll, "NtOpenSymbolicLinkObject");
            if (!NtOpenSymbolicLinkObject) return 1;

            NtQuerySymbolicLinkObject_t NtQuerySymbolicLinkObject = (NtQuerySymbolicLinkObject_t)GetProcAddress(hNtdll, "NtQuerySymbolicLinkObject");
            if (!NtQuerySymbolicLinkObject) return 1;

            int offset = 0;
            UNICODE_STRING target;

            for (int i=0; i < retLen; i++) {
            OBJDIR_INFORMATION* entry = (OBJDIR_INFORMATION*)buffer + offset;

            if (entry->Name.Buffer == 0) break;

            wprintf(L"%s\n", entry[i].Name.Buffer);

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
    }

    printf("\n");
    return 0;
}
