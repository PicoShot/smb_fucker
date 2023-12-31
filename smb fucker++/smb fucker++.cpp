#include <windows.h>
#include <thread>
#include <iostream>
#include <netfw.h>
#include <cstdlib>
#include <string>
#include <ctime>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

void enable_firewall() {
	// ReSharper disable once CppJoinDeclarationAndAssignment
	HRESULT hr;
    INetFwPolicy2* fw_policy2 = nullptr;

    hr = CoInitialize(nullptr);
    if (FAILED(hr)) {
        std::cerr << "CoInitialize failed: " << hr << std::endl;
        return;
    }

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), reinterpret_cast<void**>(&fw_policy2));
    if (FAILED(hr)) {
        std::cerr << "CoCreateInstance failed: " << hr << std::endl;
        CoUninitialize();
        return;
    }

    VARIANT_BOOL isFirewallEnabled;
    hr = fw_policy2->get_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, &isFirewallEnabled);
    if (FAILED(hr)) {
        std::cerr << "get_Enabled failed: " << hr << std::endl;
        fw_policy2->Release();
        CoUninitialize();
        return;
    }

    if (!isFirewallEnabled) {

        hr = fw_policy2->put_FirewallEnabled(NET_FW_PROFILE2_DOMAIN, VARIANT_TRUE);
        if (FAILED(hr)) {
            std::cerr << "put_Enabled failed: " << hr << std::endl;
        }
        else {
            std::wcout << L"Working..." << std::endl;
        }
    }
    else {
        std::wcout << L"Working...." << std::endl;
    }

    fw_policy2->Release();
    CoUninitialize();
}

void AddFirewallRule() {
	INetFwPolicy2* fw_policy2 = nullptr;
    INetFwRules* fwRules = nullptr;
    INetFwRule* fwRule = nullptr;

    HRESULT hr = CoInitialize(nullptr);
    if (FAILED(hr)) {
        std::cerr << "CoInitialize failed: " << hr << std::endl;
        return;
    }

    hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwPolicy2), reinterpret_cast<void**>(&fw_policy2));
    if (FAILED(hr)) {
        std::cerr << "CoCreateInstance failed: " << hr << std::endl;
        CoUninitialize();
        return;
    }

    hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER, __uuidof(INetFwRule), reinterpret_cast<void**>(&fwRule));
    if (FAILED(hr)) {
        std::cerr << "CoCreateInstance failed: " << hr << std::endl;
        fw_policy2->Release();
        CoUninitialize();
        return;
    }

    fwRule->put_Action(NET_FW_ACTION_BLOCK);
    fwRule->put_Description(SysAllocString(L"Block connections on smb ports (PicoShot)"));
    fwRule->put_Direction(NET_FW_RULE_DIR_IN);
    fwRule->put_Name(SysAllocString(L"NETfire"));
    fwRule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
    fwRule->put_LocalPorts(SysAllocString(L"135,139,445"));
    fwRule->put_Enabled(VARIANT_TRUE);
    hr = fw_policy2->get_Rules(&fwRules);
    if (FAILED(hr)) {
        std::cerr << "get_Rules failed: " << hr << std::endl;
        fwRule->Release();
        fw_policy2->Release();
        CoUninitialize();
        return;
    }

    hr = fwRules->Add(fwRule);
    if (FAILED(hr)) {
        std::cerr << "failed: " << hr << std::endl;
    }
    else {
        std::wcout << L"closing smb ports successfully." << std::endl;
    }

    fwRule->Release();
    fwRules->Release();
    fw_policy2->Release();
    CoUninitialize();
}


void change_enable_dcom_value() {
    HKEY h_key;
    const std::wstring sub_key = L"SOFTWARE\\Microsoft\\Ole";

    const LONG open_result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, sub_key.c_str(), 0, KEY_SET_VALUE, &h_key);
    if (open_result == ERROR_SUCCESS) {
	    const std::wstring new_value = L"N";

        const LONG set_result = RegSetValueEx(h_key, L"EnableDCOM", 0, REG_SZ, reinterpret_cast<const BYTE*>(new_value.c_str()), static_cast<DWORD>(sizeof(wchar_t) * (new_value.length() + 1)));

        if (set_result == ERROR_SUCCESS) {
            std::wcout << L"smb Registry key successfully changed." << std::endl;
        }
        else {
            std::wcerr << L"Error setting registry key value. Error code: " << set_result << std::endl;
        }

        RegCloseKey(h_key);
    }
    else {
        std::wcerr << L"Error opening registry key. Error code: " << open_result << std::endl;
    }
}

void clear_dcom_protocols_values() {
    HKEY h_key;
    const std::wstring sub_key = L"SOFTWARE\\Microsoft\\Rpc";

    const LONG open_result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, sub_key.c_str(), 0, KEY_SET_VALUE, &h_key);
    if (open_result == ERROR_SUCCESS) {
	    constexpr WCHAR empty_multi_string[] = L"\0\0";

        const LONG set_result = RegSetValueEx(h_key, L"DCOM Protocols", 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(empty_multi_string), static_cast<DWORD>(sizeof(empty_multi_string)));

        if (set_result == ERROR_SUCCESS) {
            std::wcout << L"All smb values in the registry successfully cleared." << std::endl;
        }
        else {
            std::wcerr << L"Error clearing smb registry key values. Error code: " << set_result << std::endl;
        }
        RegCloseKey(h_key);
    }
    else {
        std::wcerr << L"Error opening registry key. Error code: " << open_result << std::endl;
    }
}

void shell_codes() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileName(nullptr, buffer, MAX_PATH);
    const std::wstring programPath = buffer;
    const std::wstring scriptFilename = L"smb_closer.ps1";

    const size_t last_backslash = programPath.find_last_of(L'\\');
    const std::wstring program_directory = programPath.substr(0, last_backslash + 1);

    const std::wstring script_path = program_directory + scriptFilename;

    const std::wstring command = L"powershell.exe -ExecutionPolicy Bypass -File \"" + script_path + L"\"";

    const int result = _wsystem(command.c_str());


    if (result == 0) {
        std::wcerr << L"Ok." << std::endl;
        
    }
    else {
        std::wcerr << L"Error running PowerShell script." << std::endl;
        
    }
}

int xyx(const int min, const int max) {

    std::srand(static_cast<unsigned int>(std::time(nullptr)));

    const int random = std::rand();

    return min + random % (max - min + 1);
}

int main() {
	const HANDLE console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "   _____ __  _______      ________  __________ __ __________" << std::endl;
    std::cout << "  / ___//  |/  / __ )    / ____/ / / / ____/ //_// ____/ __ \\" << std::endl;
    std::cout << "  \\__ \\/ /|_/ / __  |   / /_  / / / / /   / ,<  / __/ / /_/ /" << std::endl;
    std::cout << " ___/ / /  / / /_/ /   / __/ / /_/ / /___/ /| |/ /___/ _, _/" << std::endl;
    std::cout << "/____/_/  /_/_____/   /_/    \\____/\\____/_/ |_/_____/_/ |_|" << std::endl;
    std::cout << "                                   Copyright@ Fero,PicoShot" << std::endl;
    std::cout << "                                   Version: v3" << std::endl;
    SetConsoleTextAttribute(console_handle, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);
	const int ixa = xyx(2, 5);
	const int ixb = xyx(3, 6);
	const int ixc = xyx(1, 3);
	const int ixd = xyx(2, 5);
	const int ixe = xyx(3, 7);
    std::cout << "starting..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(ixa));
    shell_codes();
    std::this_thread::sleep_for(std::chrono::seconds(ixb));
    enable_firewall();
    std::cout << "checking system..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(ixc));
    change_enable_dcom_value();
    std::this_thread::sleep_for(std::chrono::seconds(ixd));
    clear_dcom_protocols_values();
    std::this_thread::sleep_for(std::chrono::seconds(ixe));
    AddFirewallRule();
    Sleep(3000);
    system("cls");
    SetConsoleTextAttribute(console_handle, 0x0002 | 0x0001 | 0x0008);
    std::cout << "   _____ __  _______      ________  __________ __ __________" << std::endl;
    std::cout << "  / ___//  |/  / __ )    / ____/ / / / ____/ //_// ____/ __ \\" << std::endl;
    std::cout << "  \\__ \\/ /|_/ / __  |   / /_  / / / / /   / ,<  / __/ / /_/ /" << std::endl;
    std::cout << " ___/ / /  / / /_/ /   / __/ / /_/ / /___/ /| |/ /___/ _, _/" << std::endl;
    std::cout << "/____/_/  /_/_____/   /_/    \\____/\\____/_/ |_/_____/_/ |_|" << std::endl;
    std::cout << "                                   Copyright@Fero,PicoShot" << std::endl;
    std::cout << "                                   Version: v3" << std::endl;
    SetConsoleTextAttribute(console_handle, 0x0002 | 0x0001 | 0x0004);
    std::cout << "Do you want to restart the computer? (y/n): ";

    std::string userInput;
    std::cin >> userInput;

    if (userInput == "y" || userInput == "Y") {

        system("shutdown /r /t 0");
    }
    else if (userInput == "n" || userInput == "N") {
        system("pause");
    }
    else {
        std::cout << "Invalid input. Exiting program." << std::endl;
    }

    return 0;
}
