#include <windows.h>
#include <stdio.h>
#include <iostream>

#define DUMPSTR_WNAME(os, name, a) \
    do { (os) << "-> "<< (name) << ": 0x" << std::hex << (a) << std::dec << std::endl; } while(false)

#define DUMPSTR(os, a) DUMPSTR_WNAME((os), #a, (a))

struct stub_headerx86
{
	unsigned int first_xor_key;//0x70abb50b -> 0x00
	unsigned int SIG; //0xC0DEC0DF -> 0x04
	unsigned int ImageBase;//0x08
	unsigned int Null1;//0x0C
	unsigned int StubEntryPoint;//0x10
	unsigned int headerRawAddress;//0x14
	unsigned int OriginalEntryPoint;//0x18
	unsigned int unk_VA; //0x1C
	unsigned int Null2[2];//0x20
	unsigned int code_rva1;//0x24
	unsigned int Null;//0x28
	unsigned int OffsetToStubData;//0x2C
	unsigned int Null3;
	unsigned int SizeOfBindSection; //virtual/raw size
	unsigned int unk4; //ex: 816e47b0
	unsigned int CodeSectionRVA;
	unsigned int Null4;
	unsigned int SizeOfRawTextSection;
	unsigned int Null5;
	unsigned int Reserved[20];//WIP
	unsigned int Null6[8];
	unsigned int rdata_rva1;
	unsigned int Null7;
	unsigned int rdata_rva2;
	unsigned int Null8;
	unsigned int rdata_rva3;
	unsigned int Null9;
	unsigned int rdata_rva4;
	unsigned int Null10;
	unsigned int rdata_rva5;
	unsigned int unk5;
	unsigned int unk6;
	unsigned int rdata_rva6;

	std::ostream& dump(std::ostream& os)
	{
		DUMPSTR(os, first_xor_key);
		DUMPSTR(os, SIG); 
		DUMPSTR(os, ImageBase);
		DUMPSTR(os, Null1);
		DUMPSTR(os, StubEntryPoint);
		DUMPSTR(os, headerRawAddress);
		DUMPSTR(os, OriginalEntryPoint);
		DUMPSTR(os, unk_VA); 
		//DUMPSTR(os, Null2[2]);
		DUMPSTR(os, code_rva1);
		DUMPSTR(os, Null);
		DUMPSTR(os, OffsetToStubData);
		DUMPSTR(os, Null3);
		DUMPSTR(os, SizeOfBindSection); 
		DUMPSTR(os, unk4); 
		DUMPSTR(os, CodeSectionRVA);
		DUMPSTR(os, Null4);
		DUMPSTR(os, SizeOfRawTextSection);
		DUMPSTR(os, Null5);
		printf("----Skipped 20 fields----\n");
		//DUMPSTR(os, Reserved[20]);
		//DUMPSTR(os, Null6[8]);
		DUMPSTR(os, rdata_rva1);
		DUMPSTR(os, Null7);
		DUMPSTR(os, rdata_rva2);
		DUMPSTR(os, Null8);
		DUMPSTR(os, rdata_rva3);
		DUMPSTR(os, Null9);
		DUMPSTR(os, rdata_rva4);
		DUMPSTR(os, Null10);
		DUMPSTR(os, rdata_rva5);
		DUMPSTR(os, unk5);
		DUMPSTR(os, unk6);
		DUMPSTR(os, rdata_rva6);
		return os;
	}
};

class SteamPE {
private:
	DWORD_PTR buffer;
	IMAGE_DOS_HEADER* dos;
	DWORD 	e_lfanew;
	IMAGE_NT_HEADERS* nt;
	IMAGE_FILE_HEADER* file;
	IMAGE_OPTIONAL_HEADER32* optional;
	DWORD   offsetToSectionHeaders;
	DWORD  second_decryption_key;
	DWORD_PTR stub_headerOffset;

public:
	SteamPE(DWORD_PTR _buffer) {
		this->buffer = _buffer;
		this->dos = reinterpret_cast<IMAGE_DOS_HEADER*>(_buffer);
		this->e_lfanew = dos->e_lfanew;
		this->nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(_buffer + e_lfanew);
		this->file = reinterpret_cast<IMAGE_FILE_HEADER*>(&nt->FileHeader);
		this->optional = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader);
		this->offsetToSectionHeaders = e_lfanew + sizeof(IMAGE_NT_HEADERS32);
	}

	IMAGE_SECTION_HEADER* FindSection(LPCSTR _name) {
		DWORD_PTR sectionHeadersStart = this->buffer + this->offsetToSectionHeaders;
		DWORD sectionHeaderSize = 40;
		WORD  numberOfSections = this->file->NumberOfSections;

		while (strcmp(reinterpret_cast<LPCSTR>(sectionHeadersStart), _name) != 0 && numberOfSections)
		{
			sectionHeadersStart += sectionHeaderSize;
			numberOfSections--;
		}

		return reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart);
	}

	DWORD RVAtoOffset(DWORD_PTR _rva)
	{
		DWORD_PTR sectionHeadersStart = this->buffer + this->offsetToSectionHeaders;
		DWORD     sectionHeaderSize = 40;
		WORD      numberOfSections = this->file->NumberOfSections;

		while (reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart)->VirtualAddress < _rva && numberOfSections) {
			sectionHeadersStart += sectionHeaderSize;
			numberOfSections--;
		}

		IMAGE_SECTION_HEADER* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart-sectionHeaderSize);

		return _rva-section->VirtualAddress+section->PointerToRawData;
	}

	DWORD offsetoRVA(DWORD_PTR _offset) {
		DWORD_PTR sectionHeadersStart = this->buffer + this->offsetToSectionHeaders;
		DWORD sectionHeaderSize = 40;
		WORD   numberOfSections = this->file->NumberOfSections;

		while (_offset > reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart)->PointerToRawData && numberOfSections) {
			sectionHeadersStart += sectionHeaderSize;
			numberOfSections--;
		}

		IMAGE_SECTION_HEADER* section = reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart - sectionHeaderSize);

		return _offset - section->PointerToRawData + section->VirtualAddress;
	}

	bool isPE32() {
		return optional->Magic == 0x10b;
	}

	bool isProtected() {
		return *(DWORD*)FindSection(".bind");
	}

	stub_headerx86* DecryptBindHeader() {

		DWORD_PTR StubEntryPointOffset = RVAtoOffset((DWORD_PTR)this->optional->AddressOfEntryPoint);

		printf("[+] Stub EP: 0x%x\n", StubEntryPointOffset);

		this->stub_headerOffset = StubEntryPointOffset - sizeof(struct stub_headerx86);
		DWORD* stub_header = (DWORD*)(this->buffer + this->stub_headerOffset);
		DWORD* decrypted_header = stub_header;

		printf("[+] Using key: 0x%x\n", *stub_header);

		DWORD  currentField = NULL;
		DWORD  lastField = NULL;

		for (; (DWORD_PTR)stub_header < this->buffer + StubEntryPointOffset;stub_header++)
		{
			currentField = *stub_header;

			*stub_header ^= lastField;

			lastField = currentField;
		}

		this->second_decryption_key = lastField;

		return reinterpret_cast<stub_headerx86*>(decrypted_header);
	}

	DWORD getSizeOfSteamDRMPKeys() {
		return ((reinterpret_cast<stub_headerx86*>(this->buffer + this->stub_headerOffset)->OffsetToStubData) + 0xF0) & 0xFFFFFFF0;
	}

	DWORD* DecryptKeysForSteamDRMP() {
		IMAGE_SECTION_HEADER* bindSectionHeader = FindSection(".bind");
		DWORD_PTR startOfBindSection = this->buffer+bindSectionHeader->PointerToRawData;
		DWORD     sizeOfData = getSizeOfSteamDRMPKeys();

		DWORD  decryption_key = this->second_decryption_key;
		DWORD  current_field = 0;

		for (;startOfBindSection < startOfBindSection + (sizeOfData/4); startOfBindSection++)
		{
			current_field = *(DWORD*)startOfBindSection;
			*(DWORD*)startOfBindSection ^= decryption_key;
			decryption_key = current_field;
		}

		return (DWORD*)startOfBindSection;
	}
};

int main(int argc, char* argv[]) {

	if (argc < 2) {
		return -1;
	}

	if (!strlen(argv[1]))
	{
		return -1;
	}


	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("{Invalid Handle Value %x}", (DWORD)hFile);
		return -1;
	}

	DWORD fileSize = GetFileSize(hFile, NULL);

	if (!fileSize)
	{
		printf("{Cannot get file size.}");
		return -1;
	}

	BYTE* buffer = new BYTE[fileSize];

	if (!ReadFile(hFile, reinterpret_cast<LPVOID>(buffer), fileSize, NULL, NULL)) {
		printf("{Failed reading file}");
		return -1;
	}

	printf("[!] Step 1: Parsing PE file\n");

	SteamPE pe((DWORD_PTR)buffer);

	if (!pe.isPE32())
	{
		printf("{File is not a PE32}");
		return -1;
	}

	if (!pe.isProtected())
	{
		printf("{File does not have a steam stub}");
		return -1;
	}

	printf("[!] Step 2: Decrypting Stub Header\n");

	stub_headerx86* stub_header = pe.DecryptBindHeader();

	printf("[!] Step 3: DUMP\n");

	stub_header->dump(std::cout);

	printf("[!] Step 3: Decrypting keys array\n");

	DWORD sizeOfKeys = pe.getSizeOfSteamDRMPKeys();
	DWORD* keys = pe.DecryptKeysForSteamDRMP();

	for (; (DWORD_PTR)keys < (DWORD_PTR)keys + sizeOfKeys; keys++)
	{
		printf("0x%x\t", *keys);
	}

	delete[] buffer;
	CloseHandle(hFile);
	return 0;
}