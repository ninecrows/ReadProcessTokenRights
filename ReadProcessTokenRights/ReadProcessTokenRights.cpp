#include "CommonHeaders.h"

#include <iostream>

int main()
{
	int result(0);

	std::cout << "Starting up\n";

	HANDLE thisprocess(GetCurrentProcess());
	if (thisprocess == 0)
	{
		result = 1;
		std::cerr << "Failed to get process " << GetLastError() << "\n";
	}
	else
	{
		std::cout << "Process handle " << thisprocess << "\n";
	}

	HANDLE tokenhandle(nullptr);
	if (result == 0)
	{
		// TOKEN_QUERY
		// TOKEN_ADJUST_PRIVILEGES
		// TOKEN_READ
		// TOKEN_WRITE
		BOOL ok(OpenProcessToken(thisprocess, TOKEN_ALL_ACCESS, &tokenhandle));
		if (!ok)
		{
			result = 2;
			std::cerr << "Failed to open process token " << GetLastError() << "\n";
		}
		else
		{
			std::cout << "Process token " << int(tokenhandle) << "\n";
		}
	}

	// SeBackupPrivilege
	// SeRestorePrivilege
	// SeTcbPrivilege
	// SeCreateSymbolicLinkPrivilege

	bool havepriv = true;
	LUID backupluid;
	{
		BOOL ok(LookupPrivilegeValueA(nullptr, "SeBackupPrivilege" /*"SeBackupPrivilege"*/, &backupluid));
		if (!ok)
		{
			std::cerr << "Cannot find priv " << GetLastError() << "\n";
			havepriv = false;
		}
	}

	if (result == 0)
	{
		// Messy here but assume we don't have the priv unless we find it. Incoming state tells us whether the LUID was found.
		bool seekpriv = havepriv;
		havepriv = false;

		void* buffer(operator new(2048));
		DWORD returnLength(2048);
		BOOL ok(GetTokenInformation(tokenhandle, TokenPrivileges, buffer, 2048, &returnLength));
		if (!ok)
		{
			result = 3;
			std::cerr << "Failed to get process token information " << GetLastError() << "\n";
		}
		else
		{
			auto privs = (TOKEN_PRIVILEGES*)buffer;
			std::cout << "Found " << privs->PrivilegeCount << " items\n";
			for (int ct = 0; ct < privs->PrivilegeCount; ct++)
			{
				LUID_AND_ATTRIBUTES* privilege = privs->Privileges + ct;
				std::cout << "    LUID: " << privilege->Luid.LowPart << "/" << privilege->Luid.HighPart << " Attr: " << privilege->Attributes << "\n";

				char buffer[2048];
				DWORD bufferLength(2048);
				BOOL pok(LookupPrivilegeNameA(nullptr, &(privilege->Luid), buffer, &bufferLength));

				if (pok)
				{
					std::cout << "    \"" << std::string(buffer) << "\"\n";

					if (seekpriv && (privilege->Luid.LowPart == backupluid.LowPart && privilege->Luid.HighPart == backupluid.HighPart))
					{
						havepriv = true;
					}
				}
				else
				{
					std::cerr << "    Failed to get name " << GetLastError() << "\n";
				}
			}
		}
	}

	// If our token has the rights to request this privilege then lets try to activate it.
	if (havepriv)
	{
		TOKEN_PRIVILEGES privs;
		privs.PrivilegeCount = 1;
		privs.Privileges[0].Luid = backupluid; //{ 0, 0 };
		privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		void* buffer = operator new(2048);
		DWORD bufferLength(2048);

		BOOL ok(AdjustTokenPrivileges(tokenhandle, FALSE,
			&privs, sizeof(privs),
			(TOKEN_PRIVILEGES*)buffer, &bufferLength));

		if (!ok)
		{
			std::cerr << "Adjust token privs failed " << GetLastError() << "\n";
		}
		else
		{
			auto privlist((TOKEN_PRIVILEGES*)buffer);
			std::cout << "  Had " << privlist->PrivilegeCount << "\n";
		}
	}


	if (tokenhandle != 0)
	{
		BOOL ok(CloseHandle(tokenhandle));
		if (!ok)
		{
			std::cerr << "Failed to close handle " << GetLastError() << "\n";
		}
	}

	return result;
}

