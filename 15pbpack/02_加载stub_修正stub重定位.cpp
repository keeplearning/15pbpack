#include <iostream>
using namespace std;
#include "../stub/Conf.h"

#include <windows.h>

// 打开一个磁盘中的pe文件
HANDLE openPeFile(_In_ const char* path) {
	return CreateFileA(path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}

// 关闭文件
void closePeFile(_In_ HANDLE hFile) {
	CloseHandle(hFile);
}

// 将文件保存到指定路径中
bool savePeFile(_In_  const char* pFileData,
	_In_  int nSize,
	_In_ const char* path) {
	HANDLE hFile = CreateFileA(path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	DWORD dwWrite = 0;
	// 将内容写入到文件
	WriteFile(hFile, pFileData, nSize, &dwWrite, NULL);
	// 关闭文件句柄
	CloseHandle(hFile);
	return dwWrite == nSize;
}

// 获取文件内容和大小
char* getFileData(_In_ const char* pFilePath,
	_Out_opt_ int* nFileSize = NULL) {
	// 打开文件
	HANDLE hFile = openPeFile(pFilePath);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;
	// 获取文件大小
	DWORD dwSize = GetFileSize(hFile, NULL);
	if (nFileSize)
		*nFileSize = dwSize;
	// 申请对空间
	char* pFileBuff = new char[dwSize];
	memset(pFileBuff, 0, dwSize);
	// 读取文件内容到堆空间
	DWORD dwRead = 0;
	ReadFile(hFile, pFileBuff, dwSize, &dwRead, NULL);
	CloseHandle(hFile);
	// 将堆空间返回
	return pFileBuff;
}

// 释放文件内容
void freeFileData(_In_  char* pFileData) {
	delete[] pFileData;
}

//获取DOS头
IMAGE_DOS_HEADER* getDosHeader(_In_  char* pFileData) {
	return (IMAGE_DOS_HEADER *)pFileData;
}

// 获取NT头
IMAGE_NT_HEADERS* getNtHeader(_In_  char* pFileData) {
	return (IMAGE_NT_HEADERS*)(getDosHeader(pFileData)->e_lfanew + (SIZE_T)pFileData);
}

//获取文件头
IMAGE_FILE_HEADER* getFileHeader(_In_  char* pFileData) {
	return &getNtHeader(pFileData)->FileHeader;
}

//获取扩展头
IMAGE_OPTIONAL_HEADER* getOptionHeader(_In_  char* pFileData) {
	return &getNtHeader(pFileData)->OptionalHeader;
}

// 获取指定名字的区段头
IMAGE_SECTION_HEADER* getSection(_In_ char* pFileData,
	_In_  const char* scnName)//获取指定名字的区段
{
	// 获取区段格式
	DWORD dwScnCount = getFileHeader(pFileData)->NumberOfSections;
	// 获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pFileData));
	char buff[10] = { 0 };
	// 遍历区段
	for (DWORD i = 0; i < dwScnCount; ++i) {
		memcpy_s(buff, 8, (char*)pScn[i].Name, 8);
		// 判断是否是相同的名字
		if (strcmp(buff, scnName) == 0)
			return pScn + i;
	}
	return nullptr;
}


// 获取最后一个区段头
IMAGE_SECTION_HEADER* getLastSection(_In_ char* pFileData)// 获取最后一个区段
{
	// 获取区段个数
	DWORD dwScnCount = getFileHeader(pFileData)->NumberOfSections;
	// 获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(getNtHeader(pFileData));
	// 得到最后一个有效的区段
	return pScn + (dwScnCount - 1);
}

// 计算对齐大小
int aligment(_In_ int size, _In_  int aliginment) {
	return (size) % (aliginment) == 0 ? (size) : ((size) / (aliginment)+1)* (aliginment);
}

void addSection(char*& pFileData,/*被添加区段的PE文件的数据*/
	int&   nFileSize/*PE文件数据的字节数*/,
	const char* pNewSecName,/*新区段的名字*/
	int   nSecSize,/*新区段的字节数*/
	const void* pSecData/*新区段的数据*/)
{
	// 1. 修改文件头的区段个数
	getFileHeader(pFileData)->NumberOfSections++;
	// 2. 修改新区段头
	IMAGE_SECTION_HEADER* pScn = getLastSection(pFileData);
	// 2.1 区段名
	memcpy(pScn->Name, pNewSecName, 8);
	// 2.2 区段的大小
	// 2.2.1 实际大小
	pScn->Misc.VirtualSize = nSecSize;
	// 2.2.2 对齐后的大小
	pScn->SizeOfRawData = aligment(nSecSize,
		getOptionHeader(pFileData)->FileAlignment);
	// 2.3 区段的位置
	// 2.3.1 文件的偏移 = 对齐后的文件大小
	pScn->PointerToRawData = aligment(nFileSize,
		getOptionHeader(pFileData)->FileAlignment);

	// 2.3.2 内存的偏移 = 上一个区段的内存偏移的结束位置
	IMAGE_SECTION_HEADER* pPreSection = NULL;
	pPreSection = pScn - 1;
	pScn->VirtualAddress = pPreSection->VirtualAddress 
		+ aligment(pPreSection->SizeOfRawData,
			getOptionHeader(pFileData)->SectionAlignment);
	// 2.4 区段的属性
	// 2.4.1 可读可写可执行
	pScn->Characteristics = 0xE00000E0;
	// 3. 设置扩展头中映像大小.
	getOptionHeader(pFileData)->SizeOfImage =
		pScn->VirtualAddress + pScn->SizeOfRawData;

	// 4. 重新分配更大的内存空间来保存新的区段数据
	int nNewSize = pScn->PointerToRawData + pScn->SizeOfRawData;
	char* pBuff = new char[nNewSize];
	memcpy(pBuff, pFileData, nFileSize);
	memcpy(pBuff + pScn->PointerToRawData,
		pSecData,
		pScn->Misc.VirtualSize);
	freeFileData(pFileData);
	
	// 修改文件大小
	pFileData = pBuff;
	nFileSize = nNewSize;
}

struct StubDll
{
	char* pFileData; // DLL的加载基址

	char* pTextData; // 代码段的数据
	DWORD dwTextDataSize; // 代码段的大小

	StubConf* pConf;// DLL中导出的全局变量
	void* start;    // DLL中导出函数
};

void loadStub(StubDll* pStub)
{
	// 将stub.dll加载到内存
	// 加载到内存只是为了更方便地获取,以及修改
	// dll的数据,并不是真正要调用dll的代码.
	pStub->pFileData = 
		(char*)LoadLibraryEx(L"stub.dll",NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (pStub->pFileData==NULL) {
		MessageBox(NULL, L"DLL加载失败", 0, 0);
		ExitProcess(0);
	}
	IMAGE_SECTION_HEADER* pTextScn;
	pTextScn = getSection(pStub->pFileData, ".text");
	pStub->pTextData = 
		pTextScn->VirtualAddress + pStub->pFileData;
	pStub->dwTextDataSize = pTextScn->Misc.VirtualSize;

	// 获取两个导出符号
	pStub->pConf = (StubConf*)
		GetProcAddress((HMODULE)pStub->pFileData,
			"g_conf");
	pStub->start = GetProcAddress((HMODULE)pStub->pFileData,
		"start");
}

void fixStubRelocation(StubDll* stub/*stub.dll在内存中的信息*/,
	char* pFileData, /*被加壳程序的文件数据缓冲区*/
	DWORD dwNewScnRva)
{
	// 1. 先找到stub.dll中所有的重定位项.
	// 1.1 遍历重定位表.
	// 1.2 修改重定位(将DLL中所有的重定位数据改掉)
	//     重定位项 = 重定位项 - 当前加载基址 - 当前段首rva + 新的加载基址(被加壳程序的加载基址) + 新区段的段首RVA.
	IMAGE_BASE_RELOCATION* pRel =
		(IMAGE_BASE_RELOCATION*)
		(getOptionHeader(stub->pFileData)->DataDirectory[5].VirtualAddress + (DWORD)stub->pFileData);

	DWORD pStubTextRva = getSection(stub->pFileData, ".text")->VirtualAddress;
	while (pRel->SizeOfBlock != 0)
	{
		struct TypeOffset
		{
			WORD ofs : 12;
			WORD type : 4;
		}*typOfs = NULL;

		typOfs = (TypeOffset*)(pRel + 1);
		DWORD count = (pRel->SizeOfBlock - 8) / 2;
		for (size_t i = 0; i < count; i++)
		{
			if (typOfs[i].type == 3) {
				DWORD fixAddr = 
					typOfs[i].ofs 
					+ pRel->VirtualAddress 
					+ (DWORD)stub->pFileData;

				DWORD oldProt = 0;
				VirtualProtect((LPVOID)fixAddr, 1, PAGE_EXECUTE_READWRITE, &oldProt);
				*(DWORD*)fixAddr -= (DWORD)stub->pFileData;
				*(DWORD*)fixAddr -= pStubTextRva;
				*(DWORD*)fixAddr += getOptionHeader(pFileData)->ImageBase;
				*(DWORD*)fixAddr += dwNewScnRva;
				VirtualProtect((LPVOID)fixAddr, 1, oldProt, &oldProt);
			}
		}

		pRel = (IMAGE_BASE_RELOCATION*)
			((LPBYTE)pRel + pRel->SizeOfBlock);
	}
}

int main(int argc,char** argv )
{
	// 1. 获取被加壳程序的路径
	char path[MAX_PATH] = { 0 };
	printf(">");
	gets_s(path, MAX_PATH);


	// 加载stub.dll
	StubDll stub;
	loadStub(&stub);

	// 读取文件数据
	int nFileSize = 0;
	char* pFileData = getFileData(path, &nFileSize);



	// 将被加壳程序的信息保存到stub的导出结构体变量中.
	stub.pConf->oep = getOptionHeader(pFileData)->AddressOfEntryPoint;


	// 修正dll的重定位数据
	IMAGE_SECTION_HEADER* pLastScn = getLastSection(pFileData);
	DWORD dwNewScnRva = pLastScn->VirtualAddress + aligment(pLastScn->SizeOfRawData,getOptionHeader(pFileData)->SectionAlignment);
	fixStubRelocation(&stub, pFileData, dwNewScnRva);

	// 2. 添加新区段
	//    并把stub.dll的区段数据(区段数据的重定位已经被修正)
	//    拷贝到新区段中.
	addSection(pFileData,
		nFileSize,
		"15PBPACK",
		stub.dwTextDataSize,
		stub.pTextData/*stub的代码段数据*/);

	// 将OEP设置到新区段中(stub.dll的代码段中).
	// stub.dll中的一个VA转换成被加壳程序中的VA
	// VA - stub.dll加载基址 ==> RVA
	// RVA - stub.dll的代码段的RVA ==> 段内偏移
	// 段内偏移 + 新区段的RVA ==> 被加壳程序中的RVA
	DWORD stubStartRva = (DWORD)stub.start;
	stubStartRva -= (DWORD)stub.pFileData;
	stubStartRva -= getSection(stub.pFileData,".text" )->VirtualAddress;
	stubStartRva += getSection(pFileData, "15PBPACK")->VirtualAddress;
	getOptionHeader(pFileData)->AddressOfEntryPoint = stubStartRva;


	// 3. 另存到一个文件中.
	savePeFile(pFileData, nFileSize, "pack.exe");
	return 0;
}
