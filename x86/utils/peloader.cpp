#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "peloader.h"

#include <iostream>
#include <stdint.h>

using namespace std;


uint32_t AlignSize(uint32_t nSize, uint32_t nAlign)
{
	return ((nSize + nAlign - 1) / nAlign * nAlign);
}


bool loadPE(char* code, size_t* codeSize, char* data, size_t* dataSize, char* raw, size_t size, uint32_t* entry) {

	PIMAGE_DOS_HEADER ImageDosHeader = NULL;
	PIMAGE_NT_HEADERS32 ImageNtHeaders = NULL;
	PIMAGE_SECTION_HEADER ImageSectionHeader = NULL;
	int32_t FileAlignment, SectionAlignment, NumberOfSections, SizeOfImage, SizeOfHeaders;
	int32_t Index;
	int8_t *ImageBase;
	int32_t SizeOfNtHeaders;
	int32_t AddressOfEntryPoint = 0;
	ImageDosHeader = (PIMAGE_DOS_HEADER)raw;
	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}
	ImageNtHeaders = (PIMAGE_NT_HEADERS32)(raw + ImageDosHeader->e_lfanew);
	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}


	SizeOfNtHeaders = sizeof(ImageNtHeaders->FileHeader) + sizeof(ImageNtHeaders->Signature) + ImageNtHeaders->FileHeader.SizeOfOptionalHeader;

 	FileAlignment = ImageNtHeaders->OptionalHeader.FileAlignment;
 	SectionAlignment = ImageNtHeaders->OptionalHeader.SectionAlignment;
 	NumberOfSections = ImageNtHeaders->FileHeader.NumberOfSections;
	
// 	SizeOfImage = ImageNtHeaders->OptionalHeader.SizeOfImage;
// 	SizeOfHeaders = ImageNtHeaders->OptionalHeader.SizeOfHeaders;
// 
// 	SizeOfImage = AlignSize(SizeOfImage, SectionAlignment);
// 
// 	ImageBase = (BYTE *)ExAllocatePool(NonPagedPool, SizeOfImage);
// 	if (ImageBase == NULL)
// 	{
// 		return FALSE;
// 	}
//	memset(ImageBase, 0, SizeOfImage);
	SizeOfNtHeaders = sizeof(ImageNtHeaders->FileHeader) + sizeof(ImageNtHeaders->Signature) + ImageNtHeaders->FileHeader.SizeOfOptionalHeader;
	ImageSectionHeader = (PIMAGE_SECTION_HEADER)((uint8_t*)ImageNtHeaders + SizeOfNtHeaders);
	for (Index = 0; Index < NumberOfSections; Index++)
	{
		ImageSectionHeader[Index].SizeOfRawData = AlignSize(ImageSectionHeader[Index].SizeOfRawData, FileAlignment);
		ImageSectionHeader[Index].Misc.VirtualSize = AlignSize(ImageSectionHeader[Index].Misc.VirtualSize, SectionAlignment);
		if (ImageSectionHeader[Index].Characteristics & IMAGE_SCN_CNT_CODE) {
			AddressOfEntryPoint = ImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
			AddressOfEntryPoint -= ImageSectionHeader[Index].VirtualAddress;
			
			memcpy(code, raw + ImageSectionHeader[Index].VirtualAddress, ImageSectionHeader[Index].Misc.VirtualSize);
			*entry = AddressOfEntryPoint;
			*codeSize = ImageSectionHeader[Index].Misc.VirtualSize;
			printf("");
		}
	}



// 
// 	if (ImageSectionHeader[NumberOfSections - 1].VirtualAddress + ImageSectionHeader[NumberOfSections - 1].SizeOfRawData > SizeOfImage)
// 	{
// 		ImageSectionHeader[NumberOfSections - 1].SizeOfRawData = SizeOfImage - ImageSectionHeader[NumberOfSections - 1].VirtualAddress;
// 	}
// 	memcpy(ImageBase, raw, SizeOfHeaders);
// 
// 	for (Index = 0; Index < NumberOfSections; Index++)
// 	{
// 		DWORD FileOffset = ImageSectionHeader[Index].PointerToRawData;
// 		DWORD Length = ImageSectionHeader[Index].SizeOfRawData;
// 		DWORD ImageOffset = ImageSectionHeader[Index].VirtualAddress;
// 		RtlCopyMemory(&ImageBase[ImageOffset], &FileBuffer[FileOffset], Length);
// 	}
// 	*ImageModuleBase = ImageBase;

    return true;
}


