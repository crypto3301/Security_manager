#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <Lm.h>
#include <sddl.h>
#include <Lsalookup.h>
#include <Ntsecapi.h>
#include <vector>
#include <ntstatus.h>
#include <lmaccess.h>

#define RESET_COLOR "\033[0m" 
#define BLACK_COLOR "\033[30m"
#define RED_COLOR "\033[31m"
#define GREEN_COLOR "\033[32m"
#define YELLOW_COLOR "\033[33m"
#define BLUE_COLOR "\033[34m"
#define MAGENTA_COLOR "\033[35m"
#define CYAN_COLOR "\033[36m"
#define WHITE_COLOR "\033[37m"

void SetConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole != INVALID_HANDLE_VALUE) {
        SetConsoleTextAttribute(hConsole, color);
    }
}

enum ConsoleColor {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Yellow = 6,
    White = 7,
};

std::string welcomeMessage =
R"(
 __      __   _                    _        ___                  _ _          __  __                                ___  ___  __      ___         _               
 \ \    / /__| |__ ___ _ __  ___  (_)_ _   / __| ___ __ _  _ _ _(_) |_ _  _  |  \/  |__ _ _ _  __ _ __ _ ___ _ _   / _ \/ __| \ \    / (_)_ _  __| |_____ __ _____
  \ \/\/ / -_) / _/ _ \ '  \/ -_) | | ' \  \__ \/ -_) _| || | '_| |  _| || | | |\/| / _` | ' \/ _` / _` / -_) '_| | (_) \__ \  \ \/\/ /| | ' \/ _` / _ \ V  V (_-<
   \_/\_/\___|_\__\___/_|_|_\___| |_|_||_| |___/\___\__|\_,_|_| |_|\__|\_, | |_|  |_\__,_|_||_\__,_\__, \___|_|    \___/|___/   \_/\_/ |_|_||_\__,_\___/\_/\_//__/
                                                                       |__/                        |___/                                                          
)";



using namespace std;

#pragma comments(lib ,"Netapi32.lib") 

struct UserInfo {
    std::wstring username;
    std::wstring sid;
};

struct GroupInfo {
    std::wstring groupname;
    std::wstring sid;
};

std::vector<UserInfo> getRegisteredUsers() {
    std::vector<UserInfo> users;

    DWORD dwLevel = 1;
    LPUSER_INFO_1 pUserInfo = NULL;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;

    nStatus = NetUserEnum(NULL, dwLevel, FILTER_NORMAL_ACCOUNT, (LPBYTE*)&pUserInfo, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, NULL);

    if (nStatus == NERR_Success) {
        for (DWORD i = 0; i < dwEntriesRead; i++) {
            UserInfo user;
            user.username = pUserInfo[i].usri1_name;
            users.push_back(user);
        }
        if (pUserInfo != NULL) {
            NetApiBufferFree(pUserInfo);
            pUserInfo = NULL;
        }
    }
    else {
        SetConsoleColor(4);
        std::cerr << "Failed to retrieve user information. Error code: " << nStatus  << std::endl;
        SetConsoleColor(7);
    }

    return users;
}

PSID GetSID(const std::wstring& userName) {
    PSID pSid = nullptr;
    SID_NAME_USE sidNameUse;
    DWORD cbSid = 0;
    DWORD cbDomain = 0;

    // Получаем размер буфера для SID и имени домена
    LookupAccountName(nullptr, userName.c_str(), nullptr, &cbSid, nullptr, &cbDomain, &sidNameUse);

    if (cbSid > 0) {
        pSid = static_cast<PSID>(malloc(cbSid));
        WCHAR* pDomainName = static_cast<WCHAR*>(malloc(cbDomain * sizeof(WCHAR)));

        if (pSid != nullptr && pDomainName != nullptr) {
            // Получаем SID и имя домена
            if (!LookupAccountName(nullptr, userName.c_str(), pSid, &cbSid, pDomainName, &cbDomain, &sidNameUse)) {
                free(pSid);
                pSid = nullptr;
            }
        }

        free(pDomainName);
    }

    return pSid;
}

std::vector<GroupInfo> getGroups() {
    std::vector<GroupInfo> groups;

    DWORD dwLevel = 0;
    LOCALGROUP_INFO_0* pLocalGroupInfo = NULL;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;

    nStatus = NetLocalGroupEnum(NULL, dwLevel, (LPBYTE*)&pLocalGroupInfo, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, NULL);

    if (nStatus == NERR_Success) {
        for (DWORD i = 0; i < dwEntriesRead; i++) {
            GroupInfo group;
            group.groupname = pLocalGroupInfo[i].lgrpi0_name;
            groups.push_back(group);
        }
        if (pLocalGroupInfo != NULL) {
            NetApiBufferFree(pLocalGroupInfo);
            pLocalGroupInfo = NULL;
        }
    }
    else {
        SetConsoleColor(4);
        std::cerr << "Failed to retrieve group information. Error code: " << nStatus << std::endl;
        SetConsoleColor(7);
    }

    return groups;
}

bool userExists(const std::wstring& username) {
    USER_INFO_1* userInfo;
    DWORD dwLevel = 1;

    NET_API_STATUS nStatus = NetUserGetInfo(NULL, username.c_str(), dwLevel, (LPBYTE*)&userInfo);

    if (nStatus == NERR_Success) {
        NetApiBufferFree(userInfo);
        return true; // Пользователь существует
    }
    else if (nStatus == NERR_UserNotFound) {
        return false; // Пользователь не найден
    }
    else {
        SetConsoleColor(4);
        std::cerr << "Error checking user existence. Error code: " << nStatus << std::endl;
        SetConsoleColor(7);
        return false; // Произошла ошибка
    }
}

bool groupExists(const std::wstring& groupname) {
    LOCALGROUP_INFO_0* groupInfo;
    DWORD dwLevel = 0;

    NET_API_STATUS nStatus = NetLocalGroupGetInfo(NULL, groupname.c_str(), dwLevel, (LPBYTE*)&groupInfo);

    if (nStatus == NERR_Success) {
        NetApiBufferFree(groupInfo);
        return true; // Группа существует
    }
    else if (nStatus == NERR_GroupNotFound) {
        return false; // Группа не найдена
    }
    else {
        SetConsoleColor(4);
        std::cerr << "Error checking group existence. Error code: " << nStatus << std::endl;
        SetConsoleColor(7);
        return false; // Произошла ошибка
    }
}


bool addUser(const std::wstring& username, const std::wstring& password) {
    
    if (userExists(username)) {
        SetConsoleColor(2);
        std::wcout << "User " << username << " already exists." << std::endl;
        SetConsoleColor(7);
        return false;
    }

    USER_INFO_1 userInfo;
    userInfo.usri1_name = const_cast<wchar_t*>(username.c_str());
    userInfo.usri1_password = const_cast<wchar_t*>(password.c_str());
    userInfo.usri1_priv = USER_PRIV_USER;
    userInfo.usri1_home_dir = NULL;
    userInfo.usri1_comment = NULL;
    userInfo.usri1_flags = UF_SCRIPT;
    userInfo.usri1_script_path = NULL;

    DWORD dwLevel = 1;
    DWORD dwError = 0;

    NET_API_STATUS nStatus = NetUserAdd(NULL, dwLevel, (LPBYTE)&userInfo, &dwError);

    if (nStatus == NERR_Success) {
        SetConsoleColor(2);
        std::wcout << "User " << username << " added successfully." << std::endl;
        SetConsoleColor(7);
        return true;
    }
    else {
        SetConsoleColor(4);
        std::wcout << "Failed to add user " << username << ". Error code: " << nStatus << std::endl;
        SetConsoleColor(7);
        return false;
    }
}

bool addGroup(const std::wstring& groupname) {

    if (groupExists(groupname)) {
        SetConsoleColor(2);
        std::wcout << "Group " << groupname << " already exists." << std::endl;
        SetConsoleColor(7);
        return false;
    }

    LOCALGROUP_INFO_0 groupInfo;
    groupInfo.lgrpi0_name = const_cast<wchar_t*>(groupname.c_str());

    DWORD dwLevel = 0;
    DWORD dwError = 0;

    NET_API_STATUS nStatus = NetLocalGroupAdd(NULL, dwLevel, (LPBYTE)&groupInfo, &dwError);

    if (nStatus == NERR_Success) {
        SetConsoleColor(2);
        std::wcout << "Group " << groupname << " added successfully." << std::endl;
        SetConsoleColor(7);
        return true;
    }
    else {
        SetConsoleColor(4);
        std::wcout << "Failed to add group " << groupname << ". Error code: " << nStatus << std::endl;
        SetConsoleColor(7); 
        return false;
    }
}

bool deleteUser(std::wstring username) {
    NET_API_STATUS nStatus = NetUserDel(NULL, const_cast<LPWSTR>(username.c_str()));

    if (nStatus == NERR_Success) {
        SetConsoleColor(2);
        std::wcout << "User " << username << " deleted successfully." << std::endl;
        SetConsoleColor(7);
        return true;
    }
    else {
        SetConsoleColor(4);
        std::wcout << "Failed to delete user " << username << ". Error code: " << nStatus << std::endl;
        SetConsoleColor(7);
        return false;
    }
}

bool deleteGroup(const std::wstring& groupName) {
    NET_API_STATUS nStatus = NetLocalGroupDel(NULL, groupName.c_str());

    if (nStatus == NERR_Success) {
        SetConsoleColor(2);
        std::wcout << L"Группа " << groupName << L" успешно удалена." << std::endl;
        SetConsoleColor(7);
        return true;
    }
    else {
        SetConsoleColor(4);
        std::wcout << L"Не удалось удалить группу " << groupName << L". Код ошибки: " << nStatus << std::endl;
        SetConsoleColor(7);
        return false;
    }
}


bool AddPrivileges(const std::wstring& userName, const std::wstring privileges[], size_t privilegesCount) {
    HANDLE hPolicy;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    PSID pSid;
    // Инициализация LSA_OBJECT_ATTRIBUTES
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
    // Открываем политику безопасности
    NTSTATUS nts = LsaOpenPolicy(nullptr, &ObjectAttributes, POLICY_ALL_ACCESS, &hPolicy);
    if (nts != STATUS_SUCCESS) {
        SetConsoleColor(4);
        std::cout << "Ошибка при открытии политики безопасности. Код ошибки: " << nts << std::endl;
        SetConsoleColor(7);
        return false;
    }
    // Получаем SID для указанного имени пользователя
    pSid = GetSID(userName);

    if (pSid == nullptr) {
        SetConsoleColor(4);
        std::wcout << L"Ошибка при получении SID для пользователя " << userName << std::endl;
        SetConsoleColor(7);
        LsaClose(hPolicy);
        return false;
    }

    // Создаем массив LSA_UNICODE_STRING для привилегий
    LSA_UNICODE_STRING* lsaPrivileges = new LSA_UNICODE_STRING[privilegesCount];

    for (size_t i = 0; i < privilegesCount; ++i) {
        lsaPrivileges[i].Buffer = const_cast<LPWSTR>(privileges[i].c_str());
        lsaPrivileges[i].Length = static_cast<USHORT>(privileges[i].length() * sizeof(wchar_t));
        lsaPrivileges[i].MaximumLength = lsaPrivileges[i].Length + sizeof(wchar_t);
    }

    // Добавляем привилегии к пользователю
    nts = LsaAddAccountRights(hPolicy, pSid, lsaPrivileges, static_cast<ULONG>(privilegesCount));

    // Освобождаем память, выделенную для буферов привилегий и SID
    delete[] lsaPrivileges;
    FreeSid(pSid);
    // Закрываем политику безопасности
    LsaClose(hPolicy);
    if (nts == STATUS_SUCCESS) {
        SetConsoleColor(2);
        std::wcout << L"Привилегии успешно добавлены для пользователя " << userName << std::endl;
        SetConsoleColor(7);
        return true;
    }
    else if (nts == STATUS_ACCESS_DENIED) {
        SetConsoleColor(4);
        std::cout << "Access denied" << std::endl;
        SetConsoleColor(7);
    }
    else {
        SetConsoleColor(4);
        std::wcout << L"Ошибка при добавлении привилегий. Код ошибки: " << nts << std::endl;
        SetConsoleColor(7);
    }

    return false;
}


bool RemovePrivileges(const std::wstring& userName, const std::wstring privileges[], size_t privilegesCount) {
    HANDLE hPolicy;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    PSID pSid;

    // Инициализация LSA_OBJECT_ATTRIBUTES
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    // Открываем политику безопасности
    NTSTATUS nts = LsaOpenPolicy(nullptr, &ObjectAttributes, POLICY_ALL_ACCESS, &hPolicy);

    if (nts != STATUS_SUCCESS) {
        SetConsoleColor(4);
        std::wcerr << L"Ошибка при открытии политики безопасности. Код ошибки: " << nts << std::endl;
        SetConsoleColor(7);
        return false;
    }

    // Получаем SID для указанного пользователя
    pSid = GetSID(userName);

    if (pSid == nullptr) {
        SetConsoleColor(4);
        std::wcerr << L"Ошибка при получении SID для пользователя " << userName << std::endl;
        SetConsoleColor(7);
        LsaClose(hPolicy);
        return false;
    }

    // Создаем массив LSA_UNICODE_STRING для привилегий
    LSA_UNICODE_STRING* lsaPrivileges = new LSA_UNICODE_STRING[privilegesCount];

    for (size_t i = 0; i < privilegesCount; ++i) {
        lsaPrivileges[i].Buffer = const_cast<LPWSTR>(privileges[i].c_str());
        lsaPrivileges[i].Length = static_cast<USHORT>(privileges[i].length() * sizeof(wchar_t));
        lsaPrivileges[i].MaximumLength = lsaPrivileges[i].Length + sizeof(wchar_t);
    }

    // Удаляем привилегии у пользователя
    nts = LsaRemoveAccountRights(hPolicy, pSid, FALSE, lsaPrivileges, static_cast<ULONG>(privilegesCount));

    // Освобождаем память, выделенную для буферов привилегий и SID
    delete[] lsaPrivileges;
    FreeSid(pSid);

    // Закрываем политику безопасности
    LsaClose(hPolicy);

    if (nts == STATUS_SUCCESS) {
        SetConsoleColor(3);
        std::wcout << L"Привилегии успешно удалены у пользователя " << userName <<  std::endl;
        SetConsoleColor(7);
        return true;
    }
    else if (nts == STATUS_ACCESS_DENIED) {
        SetConsoleColor(4);
        std::cout << "Access denied" << std::endl;
        SetConsoleColor(7);
    }
    else {
        SetConsoleColor(4);
        std::wcerr <<  L"Ошибка при удалении привилегий. Код ошибки: " << nts << std::endl;
        SetConsoleColor(7);
    }

    return false;
}


std::vector<std::wstring> GetPrivileges(const std::wstring& username) {
    std::vector<std::wstring> userPrivileges;
    LSA_OBJECT_ATTRIBUTES objectAttributes;
    LSA_HANDLE policyHandle = NULL;
    PSID sid = NULL;
    PLSA_UNICODE_STRING privileges = NULL;
    ULONG count = 0;
    NTSTATUS status;

    sid = GetSID(username);
    if (!sid) {
        SetConsoleColor(4);
        std::wcerr << L"Failed to retrieve SID for user " << username << std::endl;
        SetConsoleColor(7);
        return userPrivileges;
    }
    // Инициализация атрибутов объекта LSA
    ZeroMemory(&objectAttributes, sizeof(objectAttributes));
    objectAttributes.Length = sizeof(objectAttributes);

    // Открываем политику LSA для получения привилегий
    status = LsaOpenPolicy(NULL, &objectAttributes, POLICY_ALL_ACCESS, &policyHandle);
    if (status != STATUS_SUCCESS) {
        SetConsoleColor(4);
        std::cerr << "Failed to open LSA policy. Error code: " << status << std::endl;
        SetConsoleColor(7);
        LocalFree(sid);
        return userPrivileges;
    }

    // Получаем привилегии пользователя
    status = LsaEnumerateAccountRights(policyHandle, sid, &privileges, &count);
    if (status != STATUS_SUCCESS) {
        SetConsoleColor(4);
        std::cerr << "Failed to enumerate user privileges. Error code: " << status << std::endl;
        SetConsoleColor(7);
        LsaClose(policyHandle);
        LocalFree(sid);
        return userPrivileges;
    }

    // Копируем привилегии пользователя в вектор
    for (ULONG i = 0; i < count; ++i) {
        userPrivileges.push_back(std::wstring(privileges[i].Buffer, privileges[i].Length / sizeof(wchar_t)));
    }

    // Освобождаем выделенную память
    LsaFreeMemory(privileges);

    // Закрываем дескриптор политики LSA и освобождаем SID
    LsaClose(policyHandle);
    LocalFree(sid);

    return userPrivileges;
}

void SyncPrivilegesWithGroup(const std::wstring& userName, const std::wstring& groupName) {
    // Получаем привилегии пользователя
    std::vector<std::wstring> userPrivileges = GetPrivileges(userName);

    // Получаем привилегии группы
    std::vector<std::wstring> groupPrivileges = GetPrivileges(groupName);

    // Добавляем привилегии из группы, которых нет у пользователя
    for (const auto& privilege : groupPrivileges) {
        if (std::find(userPrivileges.begin(), userPrivileges.end(), privilege) == userPrivileges.end()) {
            std::vector<std::wstring> privilegeToAdd = { privilege };
            AddPrivileges(userName, privilegeToAdd.data(), privilegeToAdd.size());
        }
    }

    //// Удаляем привилегии у пользователя, которых нет в группе
    //for (const auto& privilege : userPrivileges) {
    //    if (std::find(groupPrivileges.begin(), groupPrivileges.end(), privilege) == groupPrivileges.end()) {
    //        std::vector<std::wstring> privilegeToRemove = { privilege };
    //        RemovePrivileges(userName, privilegeToRemove.data(), privilegeToRemove.size());
    //    }
    //}
}

bool AddUserToGroup(const std::wstring& userName, const std::wstring& groupName) {
    // Получаем SID пользователя и группы
    PSID pUserSid = GetSID(userName);
    if (pUserSid == nullptr) {
        SetConsoleColor(4);
        std::wcout << "Failed to retrieve SID for user " << userName << std::endl;
        SetConsoleColor(7);
        return false;
    }

    PSID pGroupSid = GetSID(groupName);
    if (pGroupSid == nullptr) {
        SetConsoleColor(4);
        std::wcout << "Failed to retrieve SID for group " << groupName << std::endl;
        SetConsoleColor(7);
        LocalFree(pUserSid);
        return false;
    }

    // Добавляем пользователя в группу
    DWORD dwError = NetLocalGroupAddMembers(NULL, groupName.c_str(), 0, (LPBYTE)&pUserSid, 1);
    if (dwError != NERR_Success) {
        SetConsoleColor(4);
        std::wcout << "Failed to add user " << userName << " to group " << groupName << ". Error code: " << dwError << std::endl;
        SetConsoleColor(7);
        LocalFree(pUserSid);
        LocalFree(pGroupSid);
        return false;
    }

    // Освобождаем ресурсы
    LocalFree(pUserSid);
    LocalFree(pGroupSid);
    SetConsoleColor(2);
    std::wcout << "User " << userName << " added to group " << groupName << " successfully." << std::endl;
    SetConsoleColor(7);

    SyncPrivilegesWithGroup(userName, groupName);

    return true;
}

bool removeUserFromGroup(const std::wstring& userName, const std::wstring& groupName) {
    // Получаем SID пользователя и группы
    PSID pUserSid = GetSID(userName);

    if (pUserSid == nullptr) {
        SetConsoleColor(4);
        std::wcout << "Failed to retrieve SID for user " << userName << std::endl;
        SetConsoleColor(7);
        return false;
    }

    PSID pGroupSid = GetSID(groupName);
    if (pGroupSid == nullptr) {
        SetConsoleColor(4);
        std::wcout << "Failed to retrieve SID for group " << groupName << std::endl;
        SetConsoleColor(7);
        free(pUserSid);
        return false;
    }

    // Удаляем пользователя из группы
    DWORD dwError = NetLocalGroupDelMembers(nullptr, groupName.c_str(), 0, (LPBYTE)&pUserSid, 1);
    if (dwError != NERR_Success) {
        SetConsoleColor(4);
        std::wcout << "Failed to remove user " << userName << " from group " << groupName << ". Error code: " << dwError << std::endl;
        SetConsoleColor(7);
        free(pUserSid);
        free(pGroupSid);
        return false;
    }

    // Освобождаем ресурсы
    free(pUserSid);
    free(pGroupSid);

    SetConsoleColor(2);

    std::wcout << "User " << userName << " removed from group " << groupName << " successfully." << std::endl;
    SetConsoleColor(7);

    SyncPrivilegesWithGroup(userName, groupName);

    return true;
}

bool CheckPrivilegeForUser(LSA_HANDLE hPolicy, PSID pSid, const wchar_t* privilegeName) {
    // Получаем привилегии пользователя
    PLSA_UNICODE_STRING privileges;
    ULONG count;
    NTSTATUS status = LsaEnumerateAccountRights(hPolicy, pSid, &privileges, &count);
    if (status != STATUS_SUCCESS) {
        SetConsoleColor(4);
        std::cerr << "Failed to enumerate user privileges. Error code: " << status << std::endl;
        SetConsoleColor(7);
        return false;
    }

    // Проверяем, есть ли заданная привилегия у пользователя
    for (ULONG i = 0; i < count; ++i) {
        if (wcscmp(privileges[i].Buffer, privilegeName) == 0) {
            LsaFreeMemory(privileges);
            return true;
        }
    }

    LsaFreeMemory(privileges);
    return false;
}


void ListUsersAndGroups() {
    // Получаем список пользователей
    std::vector<UserInfo> users = getRegisteredUsers();
    SetConsoleColor(7);
    // Выводим информацию о пользователях
    std::cout << "Registered Users:" << std::endl;
    for (const auto& user : users) {
        SetConsoleColor(3);
        std::wcout << user.username << std::endl;
        SetConsoleColor(5);
        LPWSTR pszSidString;
        ConvertSidToStringSid(GetSID(user.username), &pszSidString);
        std::wcout << "SID for user " << user.username << ": " << pszSidString << std::endl;
        LocalFree(pszSidString);
        //std::wcout << "SID: " << GetSID(user.username) << std::endl;
        SetConsoleColor(7);
    }

    // Получаем список локальных групп
    std::vector<GroupInfo> groups = getGroups();

    // Выводим информацию о группах
    std::cout << "\nLocal Groups:" << std::endl;
    for (const auto& group : groups) {
        SetConsoleColor(3);
        std::wcout << group.groupname << std::endl;
        SetConsoleColor(5);
        LPWSTR pszSidString;
        ConvertSidToStringSid(GetSID(group.groupname), &pszSidString);
        std::wcout << "SID for user " << group.groupname << ": " << pszSidString << std::endl;
        LocalFree(pszSidString);
        SetConsoleColor(7);
    }
}

void help() {

    std::cout << "   " << welcomeMessage << "\n";
    SetConsoleColor(3);
    std::cout << "   " << "to continue, select an action..." << "\n";
    std::cout << "" << "\n";
    std::cout << "[get]  " <<  "> Get a list of users and groups" << "\n";
    std::cout << "[user]  " <<  "> Add a user" << "\n";
    std::cout << "[group]  " <<  "> Add a group" << "\n";
    std::cout << "[prv]  " <<  "> Write privileges to the user/group" << "\n";
    std::cout << "[addprv]  " << "> Add privileges to the user/group" << "\n";
    std::cout << "[removeprv]  " << "> Add privileges to the user/group" << "\n";
    std::cout << "[du/dg]  " <<  "> Delete a user/group" << "\n";
    std::cout << "[move]  " <<  "> Add a user to a group" << "\n";
    std::cout << "[remove]  " <<  "> Remove a user from a group" << "\n";
    SetConsoleColor(7);
}

std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

int main(int argc, char* argv[]) {
    setlocale(LC_CTYPE, "rus");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    help();
    std::string argument;
    std::string username;
    std::string password;
    std::string prv;
    while (true) {
        std::cin >> argument;

        if ((argument == "help")) {
            help();
        }
        else if (argument == "get") {
            ListUsersAndGroups();
        }
        else if (argument == "user") {
            std::cout <<"Введите username: " << std::endl;
            std::cin >> username;
            std::cout << "Введите password: " << std::endl;
            std::cin >> password;
            addUser(StringToWString(username), StringToWString(password));
        }
        else if (argument == "group") {
            std::cout << "Введите username: " << std::endl;
            std::cin >> username;
            addGroup(StringToWString(username));
        }
        else if (argument == "prv") {
            std::vector<std::wstring> tmp{};
            std::cout << "Введите username: " << std::endl;
            std::cin >> username;
            tmp = GetPrivileges(StringToWString(username));
            for (auto& i : tmp) {
                std::wcout << i << std::endl;
            }

        }
        else if (argument == "addprv") {
            std::vector<std::wstring> Privileges = {};
            std::cout << "Введите username: " << std::endl;
            std::cin >> username;
            std::cout << "Введите prv: " << std::endl;
            std::cin >> prv;
            Privileges.push_back(StringToWString(prv));
            AddPrivileges(StringToWString(username), Privileges.data(), Privileges.size());

        }
        else if (argument == "removeprv") {
            std::vector<std::wstring> Privileges = {};
            std::cout << "Введите username: " << std::endl;
            std::cin >> username;
            std::cout << "Введите prv: " << std::endl;
            std::cin >> prv;
            Privileges.push_back(StringToWString(prv));
            RemovePrivileges(StringToWString(username), Privileges.data(), Privileges.size());
        }
        else if (argument == "du") {
            std::cout << "Введите username: " << std::endl;
            std::cin >> username;
            deleteUser(StringToWString(username));
        }
        else if (argument == "dg") {
            std::cout << "Введите username: " << std::endl;
            std::cin >> username;
            deleteGroup(StringToWString(username));
        }
        else if (argument == "move") {
            std::cout << "Введите username: " << std::endl;
            std::cin >> username;
            std::cout << "Введите password: " << std::endl;
            std::cin >> password;
            AddUserToGroup(StringToWString(username), StringToWString(password));
        }
        else if (argument == "remove") {
            std::cout << "Введите username: " << std::endl;
            std::cin >> username;
            std::cout << "Введите password: " << std::endl;
            std::cin >> password;
            removeUserFromGroup(StringToWString(username), StringToWString(password));
        }
        
    }

    return 0;
}
