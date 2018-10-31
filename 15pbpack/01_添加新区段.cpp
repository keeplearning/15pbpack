#include <iostream>
using namespace std;


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

int main(int argc,char** argv )
{
	// 1. 获取被加壳程序的路径
	char path[MAX_PATH] = { 0 };
	printf(">");
	gets_s(path, MAX_PATH);

	// 2. 添加新区段
	int nFileSize = 0;
	char* pFileData = getFileData(path, &nFileSize);
	addSection(pFileData, nFileSize, "15PPACK", 200, "--");

	// 3. 另存到一个文件中.
	savePeFile(pFileData, nFileSize, "pack.exe");

	return 0;
}
