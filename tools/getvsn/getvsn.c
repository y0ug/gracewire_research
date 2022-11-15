#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>

#define BYTEn(x, n)   (*((BYTE*)&(x)+n))
#define BYTE1(x)   BYTEn(x,  1)         // byte 1 (counting from 0)
#define BYTE2(x)   BYTEn(x,  2)         // byte 1 (counting from 0)

int main(int argc, char *argv[]){
    DWORD VolumeSerialNumber;
    DWORD nSize = 16;
    CHAR szComputerName[16];
    
    BOOL bGetComputerName = GetComputerNameA(szComputerName, &nSize);
    nSize &= -bGetComputerName;

    GetVolumeInformation("C:\\", 0, 0, &VolumeSerialNumber, 0, 0, 0, 0);
    printf("vsn: 0x%08x\n", VolumeSerialNumber);
    printf("computername: %s\n", szComputerName);

    DWORD dwKey1, dwKey2;

    dwKey1 = 1664525 * VolumeSerialNumber + 1013904223;
    dwKey2 = HIWORD(VolumeSerialNumber) ^ HIWORD(dwKey1);
    DWORD i = 0;

    //DWORD v14 =0 , v15= 0, v16 = 0;
    BYTE val[8];

    for(int j=0; j < 8; ++j){

        switch (j) {
        case 0:
            val[j] = VolumeSerialNumber ^ dwKey1 ^ szComputerName[i];
            break;
        case 1:
            val[j] = VolumeSerialNumber ^ BYTE1(dwKey1) ^ szComputerName[i];
            break;
        case 2:
            val[j] = VolumeSerialNumber ^ BYTE2(dwKey1) ^ szComputerName[i];
            break;
        case 3:
            val[j] = VolumeSerialNumber ^ HIBYTE(HIWORD(dwKey1)) ^ szComputerName[i];
            break;
        case 4:
            val[j] = VolumeSerialNumber ^ VolumeSerialNumber ^ (13 * VolumeSerialNumber + 95) ^ szComputerName[i];
            break;
        case 5:
            val[j] = VolumeSerialNumber ^ ((unsigned __int16)(VolumeSerialNumber ^ (26125 * VolumeSerialNumber - 3233)) >> 8) ^ szComputerName[i];
            break;
        case 6:
            val[j] = VolumeSerialNumber ^ dwKey2 ^ szComputerName[i];
            break;
        case 7:
            val[j] = VolumeSerialNumber ^ HIBYTE(dwKey2) ^ szComputerName[i];
            break;
        }

        if (!nSize || i == nSize - 1) {
            i = 0;
        }
        else {
            ++i;
        }
    }


    printf("%08x%04x%04x%04x%08x%04x",
        dwKey1,
        (unsigned __int16)(VolumeSerialNumber ^ (26125 * VolumeSerialNumber - 3233)),
        (unsigned __int16)(HIWORD(VolumeSerialNumber) ^ HIWORD(dwKey1)),
        *(unsigned __int16*)val,
        *(DWORD*)&val[2],
        *(unsigned __int16*)&val[6]);
    return 0 ;
}