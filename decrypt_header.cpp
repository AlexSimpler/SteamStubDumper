#include <windows.h>
#include <stdio.h>

struct stub_headerx86
{
	unsigned int first_xor_key;//0x70abb50b -> 0x00
	unsigned int SIG; //0xC0DEC0DF -> 0x04
	unsigned int ImageBase;//0x08
	unsigned int Null1;//0x0C
	unsigned int OffsetToImageBase;//0x10
	unsigned int headerRawAddress;//0x14
	unsigned int OriginalEntryPoint;//0x18
	unsigned int unk_VA; //0x1C
	unsigned int Null2[2];//0x20
	unsigned int code_rva1;//0x24
	unsigned int Null;//0x28
	unsigned int OffsetToStubHeaderFromBindSection;//0x2C
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
	unsigned int Null11;
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
	
	public:
	SteamPE(DWORD_PTR _buffer) {
		this->buffer = _buffer;
		this->dos = reinterpret_cast<IMAGE_DOS_HEADER*>(_buffer);
		this->e_lfanew =  dos->e_lfanew;
		this->nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(_buffer+e_lfanew);
		this->file  = reinterpret_cast<IMAGE_FILE_HEADER*>(&nt->FileHeader);
		this->optional = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader);
		this->offsetToSectionHeaders = e_lfanew+224;//IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
	}
	
	IMAGE_SECTION_HEADER* FindSection(LPCSTR _name){
		DWORD_PTR sectionHeadersStart = this->buffer+this->offsetToSectionHeaders;
		DWORD sectionHeaderSize   = 40;
		WORD  numberOfSections    = this->file->NumberOfSections;
		
		while(strcmp(reinterpret_cast<LPCSTR>(sectionHeadersStart),_name) != 0 && numberOfSections)
		{
			sectionHeadersStart += sectionHeaderSize;
			numberOfSections--;
		}
		
		return reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart);
	}
	
	DWORD RVAtoOffset(DWORD_PTR _rva)
	{
		DWORD_PTR sectionHeadersStart = this->buffer+this->offsetToSectionHeaders;
		DWORD     sectionHeaderSize   = 40;
		WORD      numberOfSections    = this->file->NumberOfSections;
		
		printf("First section Header Virtual Address: 0x%x", *(DWORD*)(sectionHeadersStart+0xC));
		
		while(_rva > reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart)->VirtualAddress && numberOfSections) {
			sectionHeadersStart += sectionHeaderSize;
			numberOfSections--;
		}
		
		return reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart)->PointerToRawData;
	}
	
	DWORD offsetoRVA(DWORD_PTR _offset){
		DWORD_PTR sectionHeadersStart = this->buffer+this->offsetToSectionHeaders;
		DWORD sectionHeaderSize   = 40;
		WORD   numberOfSections    = this->file->NumberOfSections;
		
		while(_offset > reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart)->PointerToRawData && numberOfSections) {
			sectionHeadersStart += sectionHeaderSize;
			numberOfSections--;
		}
		
		return reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeadersStart)->VirtualAddress;
	}
	
	bool isPE32() {
		return optional->Magic == 0x10b;
	}
	
	bool isProtected(){
		return FindSection(".bind");
	}
	
	stub_headerx86* DecryptBindHeader(){
			
		DWORD_PTR StubEntryPointOffset    = RVAtoOffset((DWORD_PTR)this->optional->AddressOfEntryPoint);
		
		printf("\t[+] Stub EP: 0x%x\n",StubEntryPointOffset);
		
		IMAGE_SECTION_HEADER* bindSectionHeader = FindSection(".bind");
		
		DWORD* stub_header = (DWORD*)(this->buffer+StubEntryPointOffset-sizeof(struct stub_headerx86));
		
		printf("\t[+] Stub Header: 0x%x\n",(DWORD_PTR)stub_header);
		
		DWORD  currentField = NULL;
		DWORD  lastField    = NULL;
		
		for(int i = 0;i < sizeof(struct stub_headerx86);i--,stub_header+1)
		{
			currentField = *stub_header;
			
			*stub_header ^= lastField;
			
			lastField    =  currentField; 
		}
		
		return reinterpret_cast<stub_headerx86*>(stub_header-sizeof(struct stub_headerx86));
	}
};

int main(int argc, char* argv[]){
	
	if(argc < 2){
		return -1;
	}
	
	if(!strlen(argv[1]))
	{
			return -1;
	}
	
	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if(hFile == INVALID_HANDLE_VALUE)
	{
			printf("{Invalid Handle Value %x}",(DWORD)hFile);
			return -1;
	}
	
	DWORD fileSize = GetFileSize(hFile, NULL);
	
	if(!fileSize)
	{
		printf("{Cannot get file size.}");
		return -1;		
	}
	
	BYTE* buffer = new BYTE[fileSize];
	
	if(!ReadFile(hFile, reinterpret_cast<LPVOID>(buffer), fileSize, NULL, NULL)) {
		printf("{Failed reading file}");
		return -1;
	}
	
	printf("[!] Step 1: Parsing PE file\n");
	
	SteamPE pe((DWORD_PTR)buffer);
	
	if(!pe.isPE32())
	{
			printf("{File is not a PE32}");
			return -1;		
	}
	
	if(!pe.isProtected())
	{
			printf("{File does not have a steam stub}");
			return -1;		
	}
		
	printf("[!] Step 2: Decrypting Stub Header\n");
	
	stub_headerx86* stub_header = pe.DecryptBindHeader();
	
	printf("Decryption Key: 0x%x", stub_header->first_xor_key);
	printf("Signature: 0x%x", stub_header->SIG);
	
	delete[] buffer;
	CloseHandle(hFile);
	return 0;
}