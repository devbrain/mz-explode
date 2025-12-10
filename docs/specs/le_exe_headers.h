// ref: http://fileformats.archiveteam.org/wiki/Linear_Executable
// ref: https://moddingwiki.shikadi.net/wiki/Linear_Executable_(LX/LE)_Format
// ref: https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/exeflat.h (this is specifically for LE VXDs)
// ref: http://www.textfiles.com/programming/FORMATS/lxexe.txt (comprehensive but actually for LX, not LE)

typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned long    dword;
typedef unsigned long    uint3;
typedef unsigned char    undefined1;
typedef unsigned long    undefined4;
typedef unsigned short    ushort;
typedef unsigned int    word;

typedef enum LE_OBJECT_FLAGS {
    LE_OBJECT_FLAG_16_16_ALIAS_REQUIRED=4096,
    LE_OBJECT_FLAG_BIG_DEFAULT_BIT_SETTING=8192,
    LE_OBJECT_FLAG_CONFORMING_FOR_CODE=16384,
    LE_OBJECT_FLAG_CONTAINS_INVALID_PAGES=128,
    LE_OBJECT_FLAG_CONTAINS_PRELOAD_PAGES=64,
    LE_OBJECT_FLAG_CONTAINS_ZEROFILL_PAGES=256,
    LE_OBJECT_FLAG_DISCARABLE=16,
    LE_OBJECT_FLAG_EXECUTABLE=4,
    LE_OBJECT_FLAG_IO_PRIVILEGE_LEVEL=32768,
    LE_OBJECT_FLAG_READABLE=1,
    LE_OBJECT_FLAG_RESIDENT=512,
    LE_OBJECT_FLAG_RESIDENT_AND_CONTIGUOUS=768,
    LE_OBJECT_FLAG_RESIDENT_AND_LONG_LOCKABLE=1024,
    LE_OBJECT_FLAG_RESOURCE=8,
    LE_OBJECT_FLAG_SHARED=32,
    LE_OBJECT_FLAG_WRITABLE=2
} LE_OBJECT_FLAGS;

typedef struct LE_OBJECT_PAGE_TABLE_ENTRY LE_OBJECT_PAGE_TABLE_ENTRY, *PLE_OBJECT_PAGE_TABLE_ENTRY;

struct LE_OBJECT_PAGE_TABLE_ENTRY {
    uint3 PageDataOffset;
    word Flags;
};

typedef struct LE_OBJECT_TABLE_ENTRY LE_OBJECT_TABLE_ENTRY, *PLE_OBJECT_TABLE_ENTRY;

struct LE_OBJECT_TABLE_ENTRY {
    dword VirtualSize;
    dword BaseRelocAddress;
    enum LE_OBJECT_FLAGS ObjectFlags;
    dword PageTableIndex;
    dword PageTableEntries;
    char Reserved[4];
};

typedef struct LE_RESIDENT_NAME_TABLE_ENTRY LE_RESIDENT_NAME_TABLE_ENTRY, *PLE_RESIDENT_NAME_TABLE_ENTRY;

struct LE_RESIDENT_NAME_TABLE_ENTRY {
    byte Length;
    char[0] Name;
};

typedef struct LE_RESOURCE_TABLE_ENTRY LE_RESOURCE_TABLE_ENTRY, *PLE_RESOURCE_TABLE_ENTRY;

struct LE_RESOURCE_TABLE_ENTRY {
    word TypeID;
    word NameID;
    dword ResourceID;
    word Object;
    dword Offset;
};

typedef struct IMAGE_LE_HEADER IMAGE_LE_HEADER, *PIMAGE_LE_HEADER;

struct IMAGE_LE_HEADER {
    char SignatureWord[2];
    byte ByteOrder;
    byte WordOrder;
    dword ExecutableFormatLevel;
    word CPUType;
    word TargetOperatingSystem;
    dword ModuleVersion;
    dword ModuleTypeFlags;
    dword NumberOfMemoryPages;
    dword InitialObjectCSNumber;
    dword InitialEIP;
    dword InitialSSObjectNumber;
    dword InitialESP;
    dword MemoryPageSize;
    dword BytesOnLastPage;
    dword FixupSectionSize;
    dword FixupSectionChecksum;
    dword LoaderSectionSize;
    dword LoaderSectionChecksum;
    dword ObjectTableOffset;
    dword ObjectTableEntries;
    dword ObjectPageMapOffset;
    dword ObjectIterateDataMapOffset;
    dword ResourceTableOffset;
    dword ResourceTableEntries;
    dword ResidentNamesTableOffset;
    dword EntryTableOffset;
    dword ModuleDirectivesTableOffset;
    dword ModuleDirectivesTableEntries;
    dword FixupPageTableOffset;
    dword FixupRecordTableOffset;
    dword ImportedModulesNameTableOffset;
    dword ImportedModulesCount;
    dword ImportedProcedureNameTableOffset;
    dword PerPageChecksumTableOffset;
    dword DataPagesOffsetFromTopOfFile;
    dword PreloadPagesCount;
    dword NonResidentNamesTableOffsetFromTopOfFile;
    dword NonResidentNamesTableLength;
    dword NonResidentNamesTableChecksum;
    dword AutomaticDataObject;
    dword DebugInformationOffset;
    dword DebugInformationLength;
    dword PreloadInstancePagesNumber;
    dword DemandInstancePagesNumber;
    dword HeapSize;
    dword StackSize;
    byte Reserved[8];
    dword WindowsVXDVersionInfoResourceOffset;
    dword WindowsVXDVersionInfoResourceLength;
    word WindowsVXDDeviceID;
    word WindowsDDKVersion;
};
