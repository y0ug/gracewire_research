// x86_64-w64-mingw32-gcc  -masm=intel -Wl,--dynamicbase -pie -Os  -eWinMainCRTStartup rtldecompress.c
#include <stdio.h>
#include <stdint.h>

#include <windows.h>
#include <tlhelp32.h>
#include <ntstatus.h>

typedef NTSTATUS(__stdcall *_RtlDecompressBuffer)(
    USHORT CompressionFormat,
    PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize,
    PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize,
    PULONG FinalUncompressedSize
    );

_RtlDecompressBuffer RtlDecompressBuffer;

void SetFileData(LPCSTR lpFilename, PBYTE lpBuffer, DWORD dwNumberOfBytesToWrite){
    DWORD dwNumberOfBytesWritten;
    BOOL bResult;
    HANDLE hFile;


    hFile = (HANDLE)CreateFile(lpFilename, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE){
        return ;
    }
    bResult = WriteFile(hFile, lpBuffer, dwNumberOfBytesToWrite, &dwNumberOfBytesWritten, NULL);
    return;
}

BYTE *GetFileData(LPCSTR lpFilename, DWORD *dwReadSize)
{
    DWORD dwSizeToRead;
    BYTE *lpBuffer;
    BOOL bResult;
    HANDLE hFile;

    *dwReadSize = 0;

    hFile = (HANDLE)CreateFile(lpFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE){
        return NULL;
    }

    dwSizeToRead = GetFileSize(hFile, NULL);
    lpBuffer = (BYTE*)VirtualAlloc(NULL, dwSizeToRead, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpBuffer == NULL){
        CloseHandle(hFile);
        return NULL;
    }

    bResult = ReadFile(hFile, lpBuffer, dwSizeToRead, dwReadSize, NULL);
    if (bResult == FALSE || dwSizeToRead != *dwReadSize){
        CloseHandle(hFile);
        VirtualFree(lpBuffer, 0 , MEM_RELEASE); 
        return NULL;
    }

    CloseHandle(hFile);
    return lpBuffer;
}

void LoadFnc(){
    HMODULE hNtdll;
    hNtdll = LoadLibrary("ntdll.dll");
    RtlDecompressBuffer = (_RtlDecompressBuffer)GetProcAddress(hNtdll, "RtlDecompressBuffer");
}

int main(int argc, char *argv[]){
    DWORD dwReadSize, dwInflateSize, dwError, dwTargetInflateSize;
    BYTE *lpData, *lpDst;

    LoadFnc();

    lpData = GetFileData(argv[1], &dwReadSize);

    if(lpData == NULL){
        printf("error: can't load file\n");
        return 1;
    }

    dwTargetInflateSize = *(DWORD*)lpData;
    //printf("inflate size %08x\n", dwTargetInflateSize);
    lpDst = (BYTE*)VirtualAlloc(NULL, dwTargetInflateSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    dwError = RtlDecompressBuffer(0x102, 
        lpDst, dwTargetInflateSize, lpData + 4, dwReadSize-4, &dwInflateSize);
    if(dwError != STATUS_SUCCESS){
        printf("error %08x\n", dwError);
        //return dwError;
    }
    SetFileData(argv[2], lpDst, dwInflateSize);
    return 0;
}