#include <pspsdk.h>
#include <psptypes.h>
#include <pspkernel.h>
#include <pspidstorage.h>
#include <pspctrl.h>
#include <pspiofilemgr.h>
#include <pspdebug.h>
#include <psppower.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libpspexploit.h"

#define printf pspDebugScreenPrintf


#define VERS    2
#define REVS    1


PSP_MODULE_INFO("LeafCleaner", 0, VERS, REVS);
PSP_MAIN_THREAD_ATTR(PSP_THREAD_ATTR_USER);

static KernelFunctions _ktbl; KernelFunctions* k_tbl = &_ktbl;


int (*_sceIdStorageReadLeaf)(u16 id, void *buf) = NULL;
int ReadKey(int leaf, char *buffer)
{
        int err;

        memset(buffer, 0, 512);
        err = _sceIdStorageReadLeaf(leaf, buffer);

        return err;
}

int (*_sceIdStorageWriteLeaf)(u16 id, void *buf) = NULL;
int (*_sceIdStorageFlush)(void) = NULL;
int WriteKey(int leaf, char *buffer)
{
        int err;

        err = _sceIdStorageWriteLeaf(leaf, buffer);
        _sceIdStorageFlush();

        return err;
}

/* Global Defines */

#define MOD_ADLER 65521

/* Global Variables */

u32 ic1003[480*272];
int ic1003Loaded;

/*********************************************************************/

unsigned int adler_32(unsigned char *data, int len)
{
    unsigned int a = 1, b = 0;
    int tlen;

    while (len) {
         tlen = len > 5550 ? 5550 : len;
         len -= tlen;
         do {
              a += *data++;
              b += a;
         } while (--tlen);
         a = (a & 0xffff) + (a >> 16) * (65536-MOD_ADLER);
         b = (b & 0xffff) + (b >> 16) * (65536-MOD_ADLER);
    }
    /* It can be shown that a <= 0x1013a here, so a single subtract will do. */
    if (a >= MOD_ADLER)
         a -= MOD_ADLER;
    /* It can be shown that b can reach 0xffef1 here. */
    b = (b & 0xffff) + (b >> 16) * (65536-MOD_ADLER);
    if (b >= MOD_ADLER)
         b -= MOD_ADLER;
    return (b << 16) | a;
}


int (*_sceCtrlReadBufferPositive)(SceCtrlData *pad, int count) = NULL;

void wait_releaseK(unsigned int buttons)
{
    SceCtrlData pad;

    _sceCtrlReadBufferPositive(&pad, 1);
    while (pad.Buttons & buttons)
    {
        k_tbl->KernelDelayThread(100000);
        _sceCtrlReadBufferPositive(&pad, 1);
    }
}

void wait_release(unsigned int buttons)
{
    SceCtrlData pad;

    sceCtrlReadBufferPositive(&pad, 1);
    while (pad.Buttons & buttons)
    {
        sceKernelDelayThread(100000);
        sceCtrlReadBufferPositive(&pad, 1);
    }
}

unsigned int wait_pressK(unsigned int buttons)
{
    SceCtrlData pad;

    _sceCtrlReadBufferPositive(&pad, 1);
    while (1)
    {
        if (pad.Buttons & buttons)
            return pad.Buttons & buttons;
        k_tbl->KernelDelayThread(100000);
        _sceCtrlReadBufferPositive(&pad, 1);
    }
    return 0;   /* never reaches here, again, just to suppress warning */
}

unsigned int wait_press(unsigned int buttons)
{
    SceCtrlData pad;

    sceCtrlReadBufferPositive(&pad, 1);
    while (1)
    {
        if (pad.Buttons & buttons)
            return pad.Buttons & buttons;
        sceKernelDelayThread(100000);
        sceCtrlReadBufferPositive(&pad, 1);
    }
    return 0;   /* never reaches here, again, just to suppress warning */
}

int confirm_cancel(void)
{
    SceCtrlData pad;

    while (1)
    {
        k_tbl->KernelDelayThread(10000);
        _sceCtrlReadBufferPositive(&pad, 1);
        if(pad.Buttons & PSP_CTRL_CROSS)
        {
            wait_releaseK(PSP_CTRL_CROSS);
            return 1;
        }
        if(pad.Buttons & PSP_CTRL_CIRCLE)
        {
            wait_releaseK(PSP_CTRL_CIRCLE);
            return 0;
        }
    }
    return 0;   /* never reaches here, this suppresses a warning */
}



int (*_sceIoRename)(const char *oldname, const char *newname) = NULL;
void new_dir(char *dir_name)
{
    char new_name[512];
    int d, err, i;

    d = k_tbl->KernelIODopen(dir_name);

    if (d >= 0)
    {
        /* directory already exists, try to rename it */
        k_tbl->KernelIODclose(d);

        for (i=0; i<10000; i++)
        {
            sprintf(new_name, "%s_%04d", dir_name, i);
            d = k_tbl->KernelIODopen(new_name);
            if (d < 0)
                break; /* directory with this name doesn't exist */
            k_tbl->KernelIODclose(d);
        }
        if (i == 10000)
            printf("\n\n ERROR: Could not rename directory %s!\n\n", dir_name);
        else
        {
            printf("\n Renaming directory %s to %s...", dir_name, new_name);
            err = _sceIoRename(dir_name, new_name);
            if (err < 0)
                printf("FAILED! Error code %X\n\n", err);
            else
                printf("PASSED!\n\n");
        }
    }

    k_tbl->KernelIOMkdir(dir_name, 0777);
}




void dump_leaves(void)
{
    char buffer[512];
    char filepath[32];
    int f, s, currleaf;
    int linecnt = 5;

    pspDebugScreenClear();
    printf("\n       If leaves directory already exists, it will be renamed.\n");
    printf("                O = back, X = dump leaves to memstick\n\n");

    if (confirm_cancel())
	{
      new_dir("ms0:/leaves");
      for (currleaf=0; currleaf<0x0141; currleaf++)
      {
          k_tbl->KernelDelayThread(10000);
		  memset(buffer, 0, sizeof(buffer));
          s = ReadKey(currleaf, buffer);
          if (s != 0) continue;
          sprintf(filepath, "ms0:/leaves/0x%04X.bin", currleaf);
          f = k_tbl->KernelIOOpen(filepath, PSP_O_WRONLY | PSP_O_CREAT, 0777);
          if (f <= 0) continue;
          printf(" Saving leaf %04X to file %s...", currleaf, filepath);
          k_tbl->KernelIOWrite(f, buffer, 512);
          k_tbl->KernelIOClose(f);
          printf(" done.\n");

          linecnt++;
          if (linecnt >= 28)
          {
              k_tbl->KernelDelayThread(1*1000*1000);
              pspDebugScreenClear();
              linecnt = 0;
          }
      }
	}

    k_tbl->KernelDelayThread(5*1000*1000);
}


void new_leaf(int leaf, char *buffer, int model)
{
    if (leaf == 4 && (model == 79 || model == 82))
    {
        int i;
        int reconstruct[38] = {
            0,0x6E,1,0x79,2,0x72,3,0x42,4,0x01,8,0x10,12,0xBB,13,0x01,
            14,0xAB,15,0x1F,16,0xD8,18,0x24,20,0x14,21,0x31,22,0x14,
            24,0x94,25,0x01,26,0x48,28,0xD8
        };
        memset(buffer, 0, 512);
        for (i = 0; i < 38; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }
    else if (leaf == 4 && model == 85)
    {
        int i;
        int reconstruct[56] = {
            0,0x6E,1,0x79,2,0x72,3,0x42,4,0x01,8,0x3E,12,0x6F,13,0xE8,
            14,0xAA,15,0xB3,16,0xD8,18,0x24,20,0x14,21,0x31,22,0x14,
            24,0x94,26,0x48,28,0xD8,52,0x80,53,0x02,70,0x36,71,0x10,
            72,0xD2,73,0x0F,74,0x20,75,0x1C,76,0x3C,77,0x05
        };
        memset(buffer, 0, 512);
        for (i = 0; i < 56; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }
	else if (leaf == 4 && model == 91)
    {
        int i;
        int reconstruct[72] = {
           0,0x6E,1,0x79,2,0x72,3,0x42,4,0x1,8,0x46,12,0xE3,13,0x90,
           14,0xB0,15,0x51,16,0xD8,18,0x24,20,0x14,21,0x31,22,0x14,23,0x1E,
           24,0x94,26,0x48,28,0xD8,52,0x80,53,0x4,70,0x36,71,0x10,72,0xD2,
           73,0xF,74,0x20,75,0x1C,76,0x3C,77,0x2,78,0x48,79,0x3C,80,0x51,
           81,0x4E,82,0xFD,83,0xFF,84,0x44 
        };
        memset(buffer, 0, 512);
        for (i = 0; i < 72; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }
	else if (leaf == 4 && model == 90)
    {
        int i;
        int reconstruct[56] = {
			0,0x6E,1,0x79,2,0x72,3,0x42,4,0x01,8,0x3E,12,0x6F,13,0xE8,
            14,0xAA,15,0xB3,16,0xD8,18,0x24,20,0x14,21,0x31,22,0x14,24,0x94,
            26,0x48,28,0xD8,52,0x80,53,0x02,70,0x36,71,0x10,72,0xD2,73,0x0F,
            74,0x20,75,0x1C,76,0x3C,77,0x05	
        };
        memset(buffer, 0, 512);
        for (i = 0; i < 56; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }

    else if (leaf == 5)
    {
        int i;
        int reconstruct[22] = {
            0,0x67,1,0x6B,2,0x6C,3,0x43,4,0x01,8,0x01,12,0xCA,13,0xD9,
            14,0xE3,15,0x9B,16,0x0A
        };
        memset(buffer, 0, 512);
        for (i = 0; i < 22; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
        if (model == 82)
            buffer[0] = 0x98; /* Chilly Willy patch */
    }
    else if (leaf == 6 && model == 79)
    {
        int i;
        int reconstruct[20] = {
            0,0x72,1,0x64,2,0x44,3,0x4D,4,0x01,8,0x03,12,0xFF,13,0xFF,
            14,0xFF,15,0xFF
        };
        memset(buffer, 0, 512);
        for (i = 0; i < 20; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }
    else if (leaf == 6 && (model == 82 || model == 85))
    {
        int i;
        int reconstruct[28] = {
            0,0x72,1,0x64,2,0x44,3,0x4D,4,0x01,8,0x07,12,0x85,13,0xBD,
            14,0x2c,15,0x75,19,0x85,20,0x83,21,0x81,22,0x80
        };
        memset(buffer, 0, 512);
        for (i = 0; i < 28; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }
	else if (leaf == 6 && (model == 91 || model == 90))
    {
        int i;
        int reconstruct[28] = {
            0,0x72,1,0x64,2,0x44,3,0x4D,4,0x01,8,0x07,12,0x85,13,0xBD,
            14,0x2C,15,0x75,19,0x85,20,0x83,21,0x81,22,0x80
        };
        memset(buffer, 0, 512);
        for (i = 0; i < 28; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }

	else if(leaf == 0x41 && model == 91)
	{
		int i;
		int reconstruct[178] = {
			0,0x4C,1,0x5,4,0xA,5,0x3,6,0x53,8,0x6F,10,0x6E,12,0x79,
            68,0x5,72,0x81,73,0x3,76,0x1A,77,0x3,78,0x22,80,0x50,82,0x53,
            84,0x50,86,0x22,88,0x20,90,0x54,92,0x79,94,0x70,96,0x65,98,0x20,
            100,0x41,140,0xC9,141,0x1,144,0x1A,145,0x3,146,0x22,148,0x50,150,0x53,
            152,0x50,154,0x22,156,0x20,158,0x54,160,0x79,162,0x70,164,0x65,166,0x20,
            168,0x42,208,0xCA,209,0x1,212,0x1A,213,0x3,214,0x22,216,0x50,218,0x53,
            220,0x50,222,0x22,224,0x20,226,0x54,228,0x79,230,0x70,232,0x65,234,0x20,
            236,0x43,276,0xCB,277,0x1,280,0x1A,281,0x3,282,0x22,284,0x50,286,0x53,
            288,0x50,290,0x22,292,0x20,294,0x54,296,0x79,298,0x70,300,0x65,302,0x20,
            304,0x44,344,0xCC,345,0x1,348,0x1A,349,0x3,350,0x22,352,0x50,354,0x53,
            356,0x50,358,0x22,360,0x20,362,0x54,364,0x79,366,0x70,368,0x65,370,0x20,
            372,0x45
		};
        memset(buffer, 0, 512);
        for (i = 0; i < 178; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
	}
	else if(leaf == 0x41 && model == 90)
	{
		int i;
		int reconstruct[178] = {
			0,0x4C,1,0x05,4,0x0A,5,0x03,6,0x53,8,0x6F,10,0x6E,12,0x79,
            68,0x05,72,0xD2,73,0x02,76,0x1A,77,0x03,78,0x22,80,0x50,82,0x53,
            84,0x50,86,0x22,88,0x20,90,0x54,92,0x79,94,0x70,96,0x65,98,0x20,
            100,0x41,140,0xC9,141,0x01,144,0x1A,145,0x03,146,0x22,148,0x50,150,0x53,
            152,0x50,154,0x22,156,0x20,158,0x54,160,0x79,162,0x70,164,0x65,166,0x20,
            168,0x42,208,0xCA,209,0x01,212,0x1A,213,0x03,214,0x22,216,0x50,218,0x53,
            220,0x50,222,0x22,224,0x20,226,0x54,228,0x79,230,0x70,232,0x65,234,0x20,
            236,0x43,276,0xCB,277,0x01,280,0x1A,281,0x03,282,0x22,284,0x50,286,0x53,
            288,0x50,290,0x22,292,0x20,294,0x54,296,0x79,298,0x70,300,0x65,302,0x20,
            304,0x44,344,0xCC,345,0x01,348,0x1A,349,0x03,350,0x22,352,0x50,354,0x53,
            356,0x50,358,0x22,360,0x20,362,0x54,364,0x79,366,0x70,368,0x65,370,0x20,
            372,0x45

		};
        memset(buffer, 0, 512);
        for (i = 0; i < 178; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
	}
    else if (leaf == 0x42)
    {
        memset(buffer, 0, 512);
    }
    else if (leaf == 0x43 && (model == 79 || model == 82))
    {
        int i;
        int reconstruct[36] = {
            0,0x55,1,0x73,2,0x74,3,0x72,4,0x53,5,0x6F,6,0x6E,7,0x79,
            12,0x50,13,0x53,14,0x50,28,0x31,29,0x2E,30,0x30,31,0x30,
            32,0x50,34,0x53,36,0x50
        };
        memset(buffer, 0, 512);
        memset(buffer, 0x20, 28);
        for (i = 0; i < 36; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }
	else if (leaf == 0x43 && model == 91 )
    {
        int i;
        int reconstruct[179] = {
			0,0x55,1,0x73,2,0x74,3,0x72,4,0x53,5,0x4F,6,0x4E,7,0x59,
			8,0x20,9,0x20,10,0x20,11,0x20,12,0x22,13,0x50,14,0x53,15,0x50,
			16,0x22,17,0x20,18,0x4D,19,0x53,20,0x20,21,0x20,22,0x20,23,0x20,
            24,0x20,25,0x20,26,0x20,27,0x20,28,0x31,29,0x2E,30,0x30,31,0x30,
            32,0x22,34,0x50,36,0x53,38,0x50,40,0x22,42,0x28,44,0x50,46,0x6C,
            48,0x61,50,0x79,52,0x53,54,0x74,56,0x61,58,0x74,60,0x69,62,0x6F,
            64,0x6E,66,0x28,68,0x52,70,0x29,72,0x50,74,0x6F,76,0x72,78,0x74,
            80,0x61,82,0x62,84,0x6C,86,0x65,88,0x29,160,0x53,161,0x4F,162,0x4E,
            163,0x59,164,0x20,165,0x20,166,0x20,167,0x20,168,0x22,169,0x50,170,0x53,
            171,0x50,172,0x22,173,0x20,174,0x53,175,0x53,176,0x20,177,0x20,178,0x20,
            179,0x20,180,0x20,181,0x20,182,0x20,183,0x20,184,0x31,185,0x2E,186,0x30,
            187,0x30
        };
        memset(buffer, 0, 512);
        memset(buffer, 0xB3, 28);
        for (i = 0; i < 179; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }
	else if (leaf == 0x43 && model == 90 )
    {
        int i;
        int reconstruct[179] = {
		0,0x55,1,0x73,2,0x74,3,0x72,4,0x53,5,0x4F,6,0x4E,7,0x59,
        8,0x20,9,0x20,10,0x20,11,0x20,12,0x22,13,0x50,14,0x53,15,0x50,
        16,0x22,17,0x20,18,0x4D,19,0x53,20,0x20,21,0x20,22,0x20,23,0x20,
        24,0x20,25,0x20,26,0x20,27,0x20,28,0x31,29,0x2E,30,0x30,31,0x30,
        32,0x22,34,0x50,36,0x53,38,0x50,40,0x22,42,0x28,44,0x50,46,0x6C,
        48,0x61,50,0x79,52,0x53,54,0x74,56,0x61,58,0x74,60,0x69,62,0x6F,
        64,0x6E,66,0x28,68,0x52,70,0x29,72,0x50,74,0x6F,76,0x72,78,0x74,
        80,0x61,82,0x62,84,0x6C,86,0x65,88,0x29	
        };
        memset(buffer, 0, 512);
        memset(buffer, 0xB3, 28);
        for (i = 0; i < 179; i+=2)
            buffer[reconstruct[i]]=reconstruct[i+1];
    }
    else if (leaf == 0x45 && (model == 79 || model == 82 || model == 90 || model == 91))
    {
    	unsigned int b;

        memset(buffer, 0, 512);
        buffer[2] = 0x01;
	    printf("\n What model is your PSP? O = PSP-X000, X = PSP-X001, %c = PSP-X004/6\n", 0xc8);
    	b = wait_pressK(PSP_CTRL_SQUARE|PSP_CTRL_CROSS|PSP_CTRL_CIRCLE);
    	wait_releaseK(PSP_CTRL_SQUARE|PSP_CTRL_CROSS|PSP_CTRL_CIRCLE);
	    switch (b)
    	{
    	    case PSP_CTRL_CROSS:
    	        buffer[0] = 0;
    	        break;
    	    case PSP_CTRL_SQUARE:
    	        buffer[0] = 2;
    	        break;
    	    case PSP_CTRL_CIRCLE:
    	        buffer[0] = 3;
    	        break;
    	    default:
    	        buffer[0] = 0;
    	        break;
    	}
    	printf(" wlan region leaf generated...");
    }
    else if (leaf == 0x46)
    {
        memset(buffer, 0, 512);
    }
    else if (leaf == 0x47)
    {
        memset(buffer, 0, 512);
        buffer[0] = 9;
    }
    else
    {
        memset(buffer, 0, 512);
		printf("no leaf generated...\n");
    }
}


int get_leaf_id(char *buffer)
{
#if DEBUG
	printf("0x%08X\n", adler_32((unsigned char*)buffer, 512));
#endif
    switch (adler_32((unsigned char*)buffer, 512))
    {
        case 0xFC220D06:
        case 0x1FD3063D:
        return 4;
        break;
        case 0x0B040A37:
        case 0x7E5309BE:
        case 0xCABA0B1D:
        case 0x85920A76:
        return 0x00010004; /* leaf 4 for 85, 90, and 91*/
        break;
        case 0x31D304AF:
        return 5; /* unpatched leaf 5 */
        break;
        case 0x93D304E0:
        return 0x00010005; /* Chilly Willy patched leaf 5 */
        break;
        case 0x2BD604AC:
        return 0x00020005; /* harleyg patched leaf 5 */
        break;
        case 0x98DD0568:
        return 6;
        break;
        case 0x73BF055C:
        return 0x00010006; /* leaf 6 for 82/86/85/91 */
        break;
        case 0xC54015F9:
        return 0x41;
        break;
        case 0xB83B171C:
        case 0x41CB176C:
        return 0x00010041; /* leaf 0x41 for 85 */
        break;
        case 0x02000001:
        return 0; /* special case - clear */
        break;
        case 0x0899163A: /* leaf 43 for 91 */
        case 0xC557081D:
        return 0x43;
        break;
        case 0xB299168F:
        case 0x5DB9110A:
        return 0x00010043; /* leaf 0x43 for 85, and 91 */
        break;
        case 0x03FE0002:
        return 0x00010045; /* WLAN for PSP-1001/2 */
        break;
        case 0x05FE0003:
        return 0x00020045; /* WLAN for PSP-100? */
        break;
        case 0x07FE0004:
        return 0x00040045; /* WLAN for PSP-1004/6 */
        break;
        case 0x09FE0005:
        return 0x00000045; /* WLAN for PSP-1000 */
        break;
		case 0x29E30015: 
        case 0x2FE30018:
        return 0x45;
        break;
        case 0x1400000A:
        return 0x47;
        break;
        default:
        return -1;
    }

}


int is_orig_hd(void)
{
    char buffer[512];

    ReadKey(0x0004, buffer);
    if (get_leaf_id(buffer) != 0) /* look for clear leaf */
        return 0;
    ReadKey(0x0005, buffer);
    if (get_leaf_id(buffer) != 4) /* look for copy of leaf 4 */
        return 0;
    ReadKey(0x0006, buffer);
    if ((get_leaf_id(buffer) & 0xFFFF) != 5) /* look for copy of any leaf 5 */
        return 0;
    ReadKey(0x0041, buffer);
    if ((get_leaf_id(buffer) & 0xFFFF) != 6) /* look for copy of any leaf 6 */
        return 0;
    ReadKey(0x0042, buffer);
    if (get_leaf_id(buffer) != 0x41) /* look for copy of leaf 0x41 */
        return 0;
    ReadKey(0x0043, buffer);
    if (get_leaf_id(buffer) != 0) /* look for clear leaf */
        return 0;
    ReadKey(0x0045, buffer);
    if (get_leaf_id(buffer) != 0x47) /* look for copy of leaf 0x47 */
        return 0;
    ReadKey(0x0046, buffer);
    if ((get_leaf_id(buffer) & 0xFFFF) != 0x45) /* look for copy of any leaf 0x45 */
        return 0;
    if (ReadKey(0x0047, buffer) == 0) /* look for no leaf */
        return 0;
    return 1;
}


void fix_orig_hd(void)
{
    char buffer[512];

    printf("\n Are you really sure you wish to do this?\n");
    printf(" Writing the PSP leaves has the potential to brick it.\n");
    printf(" Last chance to back out... O = skip, X = go for it!\n\n");
    if (!confirm_cancel())
        return;

    printf(" Fixing leaf 0x0047...");
    ReadKey(0x0045, buffer);
    WriteKey(0x0047, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0045...");
    ReadKey(0x0046, buffer);
    WriteKey(0x0045, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0046...");
    ReadKey(0x0004, buffer);
    WriteKey(0x0046, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0004...");
    ReadKey(0x0005, buffer);
    WriteKey(0x0004, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0005...");
    ReadKey(0x0006, buffer);
    buffer[1] = (char)0x6b;
    buffer[0] = (char)0x98;     /* make sure leaf 0x0005 is Chilly Willy'd */
    WriteKey(0x0005, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0006...");
    new_leaf(6, buffer, 82);
    WriteKey(0x0006, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0041...");
    ReadKey(0x0042, buffer);
    WriteKey(0x0041, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0042...");
    ReadKey(0x0043, buffer);
    WriteKey(0x0042, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0043...");
    new_leaf(0x0043, buffer, 82);
    WriteKey(0x0043, buffer);
    printf("fixed!\n");

    printf(" All leaves fixed!\n");
    sceKernelDelayThread(5*1000*1000);
}


int is_orig_sd(void)
{
    char buffer[512];

    ReadKey(0x0004, buffer);
    if (get_leaf_id(buffer) != 0) /* look for clear leaf */
        return 0;
    ReadKey(0x0005, buffer);
    if (get_leaf_id(buffer) != 4) /* look for copy of leaf 4 */
        return 0;
    ReadKey(0x0006, buffer);
    if ((get_leaf_id(buffer) & 0xFFFF) != 5) /* look for copy of any leaf 5 */
        return 0;
    ReadKey(0x0041, buffer);
    if (get_leaf_id(buffer) != 0x00010006) /* look for copy of 82/86 leaf 6 */
        return 0;
    ReadKey(0x0042, buffer);
    if (get_leaf_id(buffer) != 0x41) /* look for copy of leaf 0x41 */
        return 0;
    ReadKey(0x0043, buffer);
    if (get_leaf_id(buffer) != 0) /* look for clear leaf */
        return 0;
    ReadKey(0x0045, buffer);
    if (get_leaf_id(buffer) != 0x47) /* look for copy of leaf 0x47 */
        return 0;
    ReadKey(0x0046, buffer);
    if ((get_leaf_id(buffer) & 0xFFFF) != 0x45) /* look for copy of any leaf 0x45 */
        return 0;
    ReadKey(0x0047, buffer);
    if (get_leaf_id(buffer) != 0) /* look for clear leaf */
        return 0;
    return 1;
}


void fix_orig_sd(void)
{
    char buffer[512];

    printf("\n Are you really sure you wish to do this?\n");
    printf(" Writing the PSP leaves has the potential to brick it.\n");
    printf(" Last chance to back out... O = skip, X = go for it!\n\n");
    if (!confirm_cancel())
        return;

    printf(" Fixing leaf 0x0047...");
    ReadKey(0x0045, buffer);
    WriteKey(0x0047, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0045...");
    ReadKey(0x0046, buffer);
    WriteKey(0x0045, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0046...");
    ReadKey(0x0004, buffer);
    WriteKey(0x0046, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0004...");
    ReadKey(0x0005, buffer);
    WriteKey(0x0004, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0005...");
    ReadKey(0x0006, buffer);
    buffer[1] = (char)0x6b;
    buffer[0] = (char)0x98;     /* make sure leaf 0x0005 is Chilly Willy'd */
    WriteKey(0x0005, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0006...");
    ReadKey(0x0041, buffer);
    WriteKey(0x0006, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0041...");
    ReadKey(0x0042, buffer);
    WriteKey(0x0041, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0042...");
    ReadKey(0x0043, buffer);
    WriteKey(0x0042, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0043...");
    new_leaf(0x0043, buffer, 82);
    WriteKey(0x0043, buffer);
    printf("fixed!\n");

    printf(" All leaves fixed!\n");
    sceKernelDelayThread(5*1000*1000);
}


int is_noobz_sd(void)
{
    char buffer[512];

    ReadKey(0x0004, buffer);
    if (get_leaf_id(buffer) != 0) /* look for clear leaf */
        return 0;
    ReadKey(0x0005, buffer);
    if (get_leaf_id(buffer) != 4) /* look for copy of leaf 4 */
        return 0;
    ReadKey(0x0006, buffer);
    if ((get_leaf_id(buffer) & 0xFFFF) != 5) /* look for copy of any leaf 5 */
        return 0;
    ReadKey(0x0041, buffer);
    if (get_leaf_id(buffer) != 0x41) /* look for leaf 0x41 */
        return 0;
    ReadKey(0x0042, buffer);
    if (get_leaf_id(buffer) != 0) /* look for clear leaf */
        return 0;
    ReadKey(0x0043, buffer);
    if (get_leaf_id(buffer) != 0x43) /* look for leaf 0x43 */
        return 0;
    ReadKey(0x0045, buffer);
    if ((get_leaf_id(buffer) & 0xFFFF) != 0x45) /* look for any leaf 0x45 */
        return 0;
    ReadKey(0x0046, buffer);
    if (get_leaf_id(buffer) != 0) /* look for clear leaf */
        return 0;
    ReadKey(0x0047, buffer);
    if (get_leaf_id(buffer) != 0x47) /* look for leaf 0x47 */
        return 0;
    return 1;
}


void fix_noobz_sd(void)
{
    char buffer[512];

    printf("\n Are you really sure you wish to do this?\n");
    printf(" Writing the PSP leaves has the potential to brick it.\n");
    printf(" Last chance to back out... O = skip, X = go for it!\n\n");
    if (!confirm_cancel())
        return;

    printf(" Fixing leaf 0x0004...");
    ReadKey(0x0005, buffer);
    WriteKey(0x0004, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0005...");
    ReadKey(0x0006, buffer);
    buffer[1] = (char)0x6b;
    buffer[0] = (char)0x98;     /* make sure leaf 0x0005 is Chilly Willy'd */
    WriteKey(0x0005, buffer);
    printf("fixed!\n");

    printf(" Fixing leaf 0x0006...");
    new_leaf(0x0006, buffer, 82);
    WriteKey(0x0006, buffer);
    printf("fixed!\n");

    printf(" All leaves fixed!\n");
    sceKernelDelayThread(5*1000*1000);
}

void analyze_90()
{
    int err;
    char buffer[512];
    int failed = 0;
    unsigned int b;

    printf(" Checking leaf 0x0004...");
    err = ReadKey(4, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 4 || (err & 0xFFFF) == 4)
        printf(" okay!\n");
    else
    {
        failed = 1;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0005...");
    err = ReadKey(5, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 5 || (err & 0xFFFF) == 5)
        printf(" okay!\n");
    else
    {
        failed |= 2;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0006...");
    err = ReadKey(6, buffer);
    if (!err) {
        err = get_leaf_id(buffer);
	}
    if (err == 6 || (err & 0xFFFF) == 6)
        printf(" okay!\n");
    else
    {
        failed |= 4;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0041...");
    err = ReadKey(0x41, buffer);
    if (!err)
        err = get_leaf_id(buffer);
	if (err == 0x41 || (err & 0xFFFF) == 0x41)
        printf(" okay!\n");
    else
    {
        failed |= 8;
        printf(" failed!");
        if (err < 0x0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0x0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0x0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0042...");
    err = ReadKey(0x42, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 16;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0043...");
    err = ReadKey(0x43, buffer);
    if (!err) {
        err = get_leaf_id(buffer);
	}
    if (err == 0x43 || (err & 0xFFFF) == 0x43)
        printf(" okay!\n");
    else
    {
        failed |= 32;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0045...");
    err = ReadKey(0x45, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x45 || (err & 0xFFFF) == 0x45)
        printf(" okay!\n");
    else
    {
        failed |= 64;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0046...");
    err = ReadKey(0x46, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x46 || (err & 0xFFFF) == 0x46)
        printf(" okay!\n");
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 128;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0047...");
    err = ReadKey(0x47, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x47 || (err & 0xFFFF) == 0x47)
        printf(" okay!\n");
    else
    {
        failed |= 256;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    if (failed)
    {
        k_tbl->KernelDelayThread(5*1000*1000);
        pspDebugScreenClear();
        if (failed & 0x001)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0004.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0004...");
                new_leaf(4, buffer, 90);
                WriteKey(4, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x002)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0005.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0005...");
                new_leaf(5, buffer, 90);
                WriteKey(5, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x004)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0006.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0006...");
                new_leaf(6, buffer, 90);
                WriteKey(6, buffer);
                printf(" done!\n");
            }
        }
		if ( failed & 0x008 )
		{
            printf("\n Your PSP appears to have a bad leaf 0x0041.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0041...");
                new_leaf(0x41, buffer, 90);
                WriteKey(0x41, buffer);
                printf(" done!\n");
            }
        }

        if (failed & 0x010)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0042.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0042...");
                new_leaf(0x42, buffer, 90);
                WriteKey(0x42, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x020)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0043.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0043...");
                new_leaf(0x43, buffer, 90);
                WriteKey(0x43, buffer);
                printf(" done!\n");
            }
        }
		if (failed & 0x040)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0045.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0045...");
                new_leaf(0x45, buffer, 90);
                WriteKey(0x45, buffer);
                printf(" done!\n");
            }
        }

        if (failed & 0x080)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0046.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0046...");
                new_leaf(0x46, buffer, 90);
                WriteKey(0x46, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x100)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0047.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0047...");
                new_leaf(0x47, buffer, 90);
                WriteKey(0x47, buffer);
                printf(" done!\n");
            }
        }

        printf("\n Press any key to return to main menu.\n");
        b = wait_pressK(0xFFFF);
        wait_releaseK(0xFFFF);
        return;
    }
    else
        printf("\n\n Congratulations! Your leaves appear to be fine. \n");

    k_tbl->KernelDelayThread(5*1000*1000);
#if DEBUG
    k_tbl->KernelDelayThread(5*1000*1000);
#endif
}


void analyze_91()
{
    int err;
    char buffer[512];
    int failed = 0;
    unsigned int b;

    printf(" Checking leaf 0x0004...");
    err = ReadKey(4, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 4 || (err & 0xFFFF) == 4)
        printf(" okay!\n");
    else
    {
        failed = 1;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0005...");
    err = ReadKey(5, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 5 || (err & 0xFFFF) == 5)
        printf(" okay!\n");
    else
    {
        failed |= 2;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0006...");
    err = ReadKey(6, buffer);
    if (!err) {
        err = get_leaf_id(buffer);
	}
    if (err == 6 || (err & 0xFFFF) == 6)
        printf(" okay!\n");
    else
    {
        failed |= 4;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0041...");
    err = ReadKey(0x41, buffer);
    if (!err)
        err = get_leaf_id(buffer);
	if (err == 0x41 || (err & 0xFFFF) == 0x41)
        printf(" okay!\n");
    else
    {
        failed |= 8;
        printf(" failed!");
        if (err < 0x0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0x0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0x0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0042...");
    err = ReadKey(0x42, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 16;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0043...");
    err = ReadKey(0x43, buffer);
    if (!err) {
        err = get_leaf_id(buffer);
	}
    if (err == 0x43 || (err & 0xFFFF) == 0x43)
        printf(" okay!\n");
    else
    {
        failed |= 32;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0045...");
    err = ReadKey(0x45, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x45 || (err & 0xFFFF) == 0x45)
        printf(" okay!\n");
    else
    {
        failed |= 64;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0046...");
    err = ReadKey(0x46, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x46 || (err & 0xFFFF) == 0x46)
        printf(" okay!\n");
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 128;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0047...");
    err = ReadKey(0x47, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x47 || (err & 0xFFFF) == 0x47)
        printf(" okay!\n");
    else
    {
        failed |= 256;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    if (failed)
    {
        k_tbl->KernelDelayThread(5*1000*1000);
        pspDebugScreenClear();
        if (failed & 0x001)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0004.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0004...");
                new_leaf(4, buffer, 91);
                WriteKey(4, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x002)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0005.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0005...");
                new_leaf(5, buffer, 91);
                WriteKey(5, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x004)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0006.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0006...");
                new_leaf(6, buffer, 91);
                WriteKey(6, buffer);
                printf(" done!\n");
            }
        }
		if ( failed & 0x008 )
		{
            printf("\n Your PSP appears to have a bad leaf 0x0041.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0041...");
                new_leaf(0x41, buffer, 91);
                WriteKey(0x41, buffer);
                printf(" done!\n");
            }
        }

        if (failed & 0x010)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0042.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0042...");
                new_leaf(0x42, buffer, 91);
                WriteKey(0x42, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x020)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0043.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0043...");
                new_leaf(0x43, buffer, 91);
                WriteKey(0x43, buffer);
                printf(" done!\n");
            }
        }
		if (failed & 0x040)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0045.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0045...");
                new_leaf(0x45, buffer, 91);
                WriteKey(0x45, buffer);
                printf(" done!\n");
            }
        }

        if (failed & 0x080)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0046.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0046...");
                new_leaf(0x46, buffer, 91);
                WriteKey(0x46, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x100)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0047.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0047...");
                new_leaf(0x47, buffer, 91);
                WriteKey(0x47, buffer);
                printf(" done!\n");
            }
        }

        printf("\n Press any key to return to main menu.\n");
        b = wait_pressK(0xFFFF);
        wait_releaseK(0xFFFF);
        return;
    }
    else
        printf("\n\n Congratulations! Your leaves appear to be fine. \n");

    k_tbl->KernelDelayThread(5*1000*1000);
}



void analyze_7981()
{
    int err;
    char buffer[512];
    int failed = 0;
    unsigned int b;

    printf(" Checking leaf 0x0004...");
    err = ReadKey(4, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 4)
        printf(" okay!\n");
    else
    {
        failed = 1;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0005...");
    err = ReadKey(5, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 5)
        printf(" okay!\n");
    else
    {
        failed |= 2;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0006...");
    err = ReadKey(6, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 6)
        printf(" okay!\n");
    else
    {
        failed |= 4;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0041...");
    err = ReadKey(0x41, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x41)
        printf(" okay!\n");
    else
    {
        failed |= 8;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0042...");
    err = ReadKey(0x42, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 16;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0043...");
    err = ReadKey(0x43, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x43)
        printf(" okay!\n");
    else
    {
        failed |= 32;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0045...");
    err = ReadKey(0x45, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if ((err & 0xFFFF) == 0x45)
        printf(" okay!\n");
    else
    {
        failed |= 64;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0046...");
    err = ReadKey(0x46, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 128;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0047...");
    err = ReadKey(0x47, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x47)
        printf(" okay!\n");
    else
    {
        failed |= 256;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    if (failed)
    {
        if (failed == 0x100)
            printf("\n\n Don't worry about leaf 0x47 failing. This is just an old TA-079.\n");
        else if (failed == 0x180)
            printf("\n\n Wow, this is a REALLY old TA-079. The leaves are fine.\n");
        k_tbl->KernelDelayThread(5*1000*1000);
        pspDebugScreenClear();
        if (failed & 0x001)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0004.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0004...");
                new_leaf(4, buffer, 79);
                WriteKey(4, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x002)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0005.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0005...");
                new_leaf(5, buffer, 79);
                WriteKey(5, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x004)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0006.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0006...");
                new_leaf(6, buffer, 79);
                WriteKey(6, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x010)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0042.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0042...");
                new_leaf(0x42, buffer, 79);
                WriteKey(0x42, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x020)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0043.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0043...");
                new_leaf(0x43, buffer, 79);
                WriteKey(0x43, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x080)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0046.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0046...");
                new_leaf(0x46, buffer, 79);
                WriteKey(0x46, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x100)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0047.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0047...");
                new_leaf(0x47, buffer, 79);
                WriteKey(0x47, buffer);
                printf(" done!\n");
            }
        }

        printf("\n Press any leaf to return to main menu.\n");
        b = wait_pressK(0xFFFF);
        wait_releaseK(0xFFFF);
        return;
    }
    else
        printf("\n\n Congratulations! Your leaves appear to be fine. \n");

    k_tbl->KernelDelayThread(5*1000*1000);
}


void analyze_8286()
{
    int err;
    char buffer[512];
    int failed = 0;
    unsigned int b;

    printf(" Checking leaf 0x0004...");
    err = ReadKey(4, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 4)
        printf(" okay!\n");
    else
    {
        failed = 1;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0005...");
    err = ReadKey(5, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x00010005)
        printf(" okay! Chilly Willy patched leaf 5 found.\n");
    else
    {
        failed |= 2;
        if (err == 5)
            printf(" okay! Original unpatched leaf 5 found.\n");
        else if (err == 0x00020005)
            printf(" okay! Generic patched leaf 5 found.\n");
        else
        {
            printf(" failed!");
            if (err < 0)
                printf(" ReadKey returned code 0x%08X.\n", err);
            if (err == 0)
                printf(" This leaf is clear and shouldn't be.\n");
            if (err > 0)
                printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
        }
    }

    printf(" Checking leaf 0x0006...");
    err = ReadKey(6, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x00010006)
        printf(" okay!\n");
    else
    {
        failed |= 4;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0041...");
    err = ReadKey(0x41, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x41)
        printf(" okay!\n");
    else
    {
        failed |= 8;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0042...");
    err = ReadKey(0x42, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 16;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0043...");
    err = ReadKey(0x43, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x43)
        printf(" okay!\n");
    else
    {
        failed |= 32;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0045...");
    err = ReadKey(0x45, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if ((err & 0xFFFF) == 0x45)
        printf(" okay!\n");
    else
    {
        failed |= 64;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0046...");
    err = ReadKey(0x46, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 128;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0047...");
    err = ReadKey(0x47, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x47)
        printf(" okay!\n");
    else
    {
        failed |= 256;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    if (failed)
    {
        if (is_orig_hd())
        {
            printf("\n The PSP appears to be hard-downed. Press any leaf to fix.\n");
            b = wait_pressK(0xFFFF);
            wait_releaseK(0xFFFF);
            pspDebugScreenClear();
            fix_orig_hd();
            return;
        }
        else if (is_orig_sd())
        {
            printf("\n The PSP appears to be original soft-downed. Press any leaf to fix.\n");
            b = wait_pressK(0xFFFF);
            wait_releaseK(0xFFFF);
            pspDebugScreenClear();
            fix_orig_sd();
            return;
        }
        else if (is_noobz_sd())
        {
            printf("\n The PSP appears to be noobz soft-downed. Press any leaf to fix.\n");
            b = wait_pressK(0xFFFF);
            wait_releaseK(0xFFFF);
            pspDebugScreenClear();
            fix_noobz_sd();
            return;
        }
        k_tbl->KernelDelayThread(5*1000*1000);
        pspDebugScreenClear();
        if (failed & 0x001)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0004.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0004...");
                new_leaf(4, buffer, 82);
                WriteKey(4, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x002)
        {
            printf("\n Your PSP appears to not have a Chilly Willy patched leaf 0x0005.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0005...");
                new_leaf(5, buffer, 82);
                WriteKey(5, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x004)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0006.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0006...");
                new_leaf(6, buffer, 82);
                WriteKey(6, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x010)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0042.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0042...");
                new_leaf(0x42, buffer, 82);
                WriteKey(0x42, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x020)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0043.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0043...");
                new_leaf(0x43, buffer, 82);
                WriteKey(0x43, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x040)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0045.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0045...");
                new_leaf(0x45, buffer, 82);
                WriteKey(0x45, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x080)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0046.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0046...");
                new_leaf(0x46, buffer, 82);
                WriteKey(0x46, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x100)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0047.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0047...");
                new_leaf(0x47, buffer, 82);
                WriteKey(0x47, buffer);
                printf(" done!\n");
            }
        }

        printf("\n Press any leaf to return to main menu.\n");
        b = wait_pressK(0xFFFF);
        wait_releaseK(0xFFFF);
        return;
    }
    else
    {
        printf("\n Congratulations! Your leaves appear to be fine. \n");

        err = ReadKey(5, buffer);
        if (!err)
            err = get_leaf_id(buffer);
        if (err == 0x00010005)
        {
            printf("\n Do you wish to unpatch leaf 0x0005? Please note that an unpatched\n");
            printf("  leaf 0x0005 will brick a TA-082/86 with 1.50 or custom firmware\n");
            printf("  unless you have installed a custom IPL to prevent this.\n\n");
            printf("                  O = Leave as is, X = unpatch leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Unpatching leaf 0x0005...");
                new_leaf(5, buffer, 79); /* 79 is unpatched */
                buffer[0] = 0x67;
                WriteKey(5, buffer);
                printf(" done!\n");
            }
        }
    }

    k_tbl->KernelDelayThread(5*1000*1000);
}


void analyze_85()
{
    int err;
    char buffer[512];
    int failed = 0;
    unsigned int b;

    printf(" Checking leaf 0x0004...");
    err = ReadKey(4, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x00010004)
        printf(" okay!\n");
    else
    {
        failed = 1;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0005...");
    err = ReadKey(5, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 5)
        printf(" okay!\n");
    else
    {
        failed |= 2;
        if (err == 5)
            printf(" okay! Original unpatched leaf 5 found.\n");
        else if (err == 0x00020005)
            printf(" okay! Generic patched leaf 5 found.\n");
        else
        {
            printf(" failed!");
            if (err < 0)
                printf(" ReadKey returned code 0x%08X.\n", err);
            if (err == 0)
                printf(" This leaf is clear and shouldn't be.\n");
            if (err > 0)
                printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
        }
    }

    printf(" Checking leaf 0x0006...");
    err = ReadKey(6, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x00010006)
        printf(" okay!\n");
    else
    {
        failed |= 4;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0041...");
    err = ReadKey(0x41, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x00010041)
        printf(" okay!\n");
    else
    {
        failed |= 8;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0042...");
    err = ReadKey(0x42, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 16;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0043...");
    err = ReadKey(0x43, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x00010043)
        printf(" okay!\n");
    else
    {
        failed |= 32;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

#if 0
    printf(" Checking leaf 0x0045...");
    err = ReadKey(0x45, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if ((err & 0xFFFF) == 0x45)
        printf(" okay!\n");
    else
    {
        failed |= 64;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }
#endif

    printf(" Checking leaf 0x0046...");
    err = ReadKey(0x46, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0)
        printf(" okay!\n");
    else
    {
        failed |= 128;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        else
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    printf(" Checking leaf 0x0047...");
    err = ReadKey(0x47, buffer);
    if (!err)
        err = get_leaf_id(buffer);
    if (err == 0x47)
        printf(" okay!\n");
    else
    {
        failed |= 256;
        printf(" failed!");
        if (err < 0)
            printf(" ReadKey returned code 0x%08X.\n", err);
        if (err == 0)
            printf(" This leaf is clear and shouldn't be.\n");
        if (err > 0)
            printf(" This leaf is a copy of leaf 0x%04X.\n", err & 0xFFFF);
    }

    if (failed)
    {
        k_tbl->KernelDelayThread(5*1000*1000);
        pspDebugScreenClear();
        if (failed & 0x001)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0004.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0004...");
                new_leaf(4, buffer, 85);
                WriteKey(4, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x002)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0005.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0005...");
                new_leaf(5, buffer, 85);
                WriteKey(5, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x004)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0006.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0006...");
                new_leaf(6, buffer, 85);
                WriteKey(6, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x010)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0042.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0042...");
                new_leaf(0x42, buffer, 85);
                WriteKey(0x42, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x080)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0046.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0046...");
                new_leaf(0x46, buffer, 85);
                WriteKey(0x46, buffer);
                printf(" done!\n");
            }
        }
        if (failed & 0x100)
        {
            printf("\n Your PSP appears to have a bad leaf 0x0047.\n");
            printf("\n                    O = Leave as is, X = Fix leaf\n\n");
            if (confirm_cancel())
            {
                printf("\n Fixing leaf 0x0047...");
                new_leaf(0x47, buffer, 85);
                WriteKey(0x47, buffer);
                printf(" done!\n");
            }
        }

        printf("\n Press any leaf to return to main menu.\n");
        b = wait_pressK(0xFFFF);
        wait_releaseK(0xFFFF);
        return;
    }
    else
    {
        printf("\n Congratulations! Your leaves appear to be fine. \n");
    }

    k_tbl->KernelDelayThread(5*1000*1000);
}


/*
 * return values:
 * 0x0101 = TA_079/81
 * 0x0202 = TA_082/86
 * 0x0303 = TA_085
 *
 */

int check_mobo(void)
{
    int mobo;
    char buffer[512];

    ReadKey(0x0100, buffer);
    mobo = buffer[0x03f];

    ReadKey(0x0050, buffer);
    mobo = (mobo << 8) | buffer[0x021];

    return mobo;
}


/*
 * return values:
 * 0x03 = PSP-1000 Japan
 * 0x04 = PSP-1001 USA
 * 0x05 = PSP-1003/4 UK, Europe, Middle East, Africa
 * 0x06 = PSP-1005 Korea
 * 0x07 = PSP-1003 UK
 * 0x09 = PSP-1002 Australia, New Zealand
 * 0x0A = PSP-1006 Hong Kong, Singapore
 *
 */

int check_region(void)
{
    char buffer[512];

    ReadKey(0x0120, buffer);
    return buffer[0x03d];
}


void analyze_leaves(void)
{
	unsigned int b;

    while (1)
    {
        pspDebugScreenClear();
        printf("\n");
#if DEBUG
		printf("mobover: 0x%04X\n", check_mobo());
#endif
        switch (check_mobo())
        {
            case 0x0101:
            printf(" The IdStorage identifies the motherboard as a TA-079/81\n\n");
            break;
            case 0x0202:
            printf(" The IdStorage identifies the motherboard as a TA-082/86\n\n");
            break;
            case 0x0303:
            printf(" The IdStorage identifies the motherboard as a TA-085\n\n");
            break;
            case 0x0404:
            printf(" The IdStorage identifies the motherboard as a TA-090\n\n");
            break;
            case 0x0501:
            printf(" The IdStorage identifies the motherboard as a TA-091\n\n");
            break;
            default:
            printf(" The motherboard cannot be determined from the IdStorage\n");
            printf(" There may be a problem with the IdStorage on this PSP.\n\n");
        }
        printf(" Please note that all slim PSPs are currently TA-085 motherboards.\n");
        printf("\n     O = TA-079/81, X = TA-082/86, %c = TA-085, %c = TA-091\n", 0xd8, 0xc8);
        printf("\n     LEFT = TA-090\n\n");
        b = wait_pressK(PSP_CTRL_SQUARE|PSP_CTRL_CROSS|PSP_CTRL_CIRCLE|PSP_CTRL_TRIANGLE|PSP_CTRL_LEFT);
        wait_releaseK(PSP_CTRL_SQUARE|PSP_CTRL_CROSS|PSP_CTRL_CIRCLE|PSP_CTRL_TRIANGLE|PSP_CTRL_LEFT);
        if (b & PSP_CTRL_CIRCLE)
        {
            analyze_7981();
            return;
        }
        if (b & PSP_CTRL_CROSS)
        {
            analyze_8286();
            return;
        }
        if (b & PSP_CTRL_TRIANGLE)
        {
            analyze_85();
            return;
        }
        if (b & PSP_CTRL_SQUARE)
		{
            analyze_91();
            return;
		}
		if (b & PSP_CTRL_LEFT)
		{
            analyze_90();
            return;
		}

    }

}


int kmain_analyze() {
	int k1 = pspSdkSetK1(0);
	int ul = pspXploitSetUserLevel(8);
	pspXploitRepairKernel();
	pspXploitScanKernelFunctions(k_tbl);
	_sceIdStorageReadLeaf = (void*)pspXploitFindFunction("sceIdStorage_Service", "sceIdStorage_driver", 0xEB00C509);
	_sceIdStorageWriteLeaf = (void*)pspXploitFindFunction("sceIdStorage_Service", "sceIdStorage_driver", 0x1FA4D135);
	_sceIdStorageFlush = (void*)pspXploitFindFunction("sceIdStorage_Service", "sceIdStorage_driver", 0x3AD32523);
	_sceCtrlReadBufferPositive = (void*)pspXploitFindFunction("sceController_Service", "sceCtrl", 0x1F803938);



    SceUID kthreadID = k_tbl->KernelCreateThread("leafcleaner_thread", (void*)KERNELIFY(&analyze_leaves), 1, 0x20000, PSP_THREAD_ATTR_VFPU, NULL);
    if (kthreadID >= 0){ 
        k_tbl->KernelStartThread(kthreadID, 0, NULL);
        k_tbl->waitThreadEnd(kthreadID, NULL);
    }  

	pspSdkSetK1(k1);
	pspXploitSetUserLevel(ul);
}

int kmain_dump() {
	int k1 = pspSdkSetK1(0);
	int ul = pspXploitSetUserLevel(8);
	pspXploitRepairKernel();
	pspXploitScanKernelFunctions(k_tbl);
	_sceIdStorageReadLeaf = (void*)pspXploitFindFunction("sceIdStorage_Service", "sceIdStorage_driver", 0xEB00C509);
	_sceIdStorageWriteLeaf = (void*)pspXploitFindFunction("sceIdStorage_Service", "sceIdStorage_driver", 0x1FA4D135);
	_sceIdStorageFlush = (void*)pspXploitFindFunction("sceIdStorage_Service", "sceIdStorage_driver", 0x3AD32523);
	_sceCtrlReadBufferPositive = (void*)pspXploitFindFunction("sceController_Service", "sceCtrl", 0x1F803938);
	_sceIoRename = (void*)pspXploitFindFunction("sceIOFileManager", "IoFileMgrForKernel", 0x779103A0);



    SceUID kthreadID = k_tbl->KernelCreateThread("leafcleaner_thread", (void*)KERNELIFY(&dump_leaves), 1, 0x20000, PSP_THREAD_ATTR_VFPU, NULL);
    if (kthreadID >= 0){ 
        k_tbl->KernelStartThread(kthreadID, 0, NULL);
        k_tbl->waitThreadEnd(kthreadID, NULL);
    }  

	pspSdkSetK1(k1);
	pspXploitSetUserLevel(ul);
}

int main(void)
{
    unsigned int b;

    pspDebugScreenInit();
    pspDebugScreenSetBackColor(0x00AAAA00);
    pspDebugScreenSetTextColor(0x00ffffff);
    pspDebugScreenClear();
    sceCtrlSetSamplingCycle(0);
    sceCtrlSetSamplingMode(PSP_CTRL_MODE_DIGITAL);

    if (scePowerGetBatteryLifePercent() < 75)
    {
        printf("\n Battery is %d%%, it should be at least at 75%%.\n", scePowerGetBatteryLifePercent());
        printf(" WARNING! Using this program with a low battery can brick the PSP!\n");
        printf(" Press X to continue anyway, press anything else to quit.\n");
        b = wait_press(0xffff);
        wait_release(0xffff);
        if (!(b & PSP_CTRL_CROSS))
        {
            sceKernelDelayThread(1*1000*1000);
            sceKernelExitGame();
        }
    }

    while (1)
    {
        pspDebugScreenClear();
        printf("\n                         Leaf Cleaner v%d.%d\n", VERS, REVS);
        printf("                           by  Krazynez\n\n");
        printf("            Originally called Key Cleaner by ChillyWilly\n\n");
        printf("\n\n             O = Exit, X = Analyze leaves, %c = Dump leaves\n\n", 0xc8);
        b = wait_press(PSP_CTRL_SQUARE|PSP_CTRL_CROSS|PSP_CTRL_CIRCLE);
        wait_release(PSP_CTRL_SQUARE|PSP_CTRL_CROSS|PSP_CTRL_CIRCLE);
        if (b & PSP_CTRL_CROSS) {
			pspXploitInitKernelExploit();
			pspXploitDoKernelExploit();
            pspXploitExecuteKernel((u32)kmain_analyze);
		}
        if (b & PSP_CTRL_SQUARE) {
			pspXploitInitKernelExploit();
			pspXploitDoKernelExploit();
            pspXploitExecuteKernel((u32)kmain_dump);
		}
        if (b & PSP_CTRL_CIRCLE) {
            printf("\n\n Exiting application. Please wait for the XMB to reload.\n");
            sceKernelDelayThread(2*1000*1000);
            sceKernelExitGame();
        }
    }

    return 0;   /* never reaches here, again, just to suppress warning */
}
