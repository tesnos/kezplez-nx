//library includes
#include <string.h>
#include <stdio.h>
#include <switch.h>
#include <stdbool.h>
#include <mbedtls/sha256.h>

//hactool includes
#include "hactool/extkeys.h"
#include "hactool/nca.h"
#include "hactool/packages.h"
#include "hactool/pki.h"
#include "hactool/types.h"
#include "hactool/utils.h"

//local includes
#include "graphics/gui.h"
#include "util.h"

//internal definitions
#define BOOT0_SIZE 0x400000
char* PKG11_LOC;
#define PKG11_REALBEGIN 0x100000
#define PKG11_SIZE 0x40000
char BOOT0_DATA[BOOT0_SIZE];
char PKG11_DATA[PKG11_SIZE];

#define BCPKG_21_SIZE 0x800000
#define PKG21_BEGIN 0x4000
#define PKG21_SIZE (BCPKG_21_SIZE - PKG21_BEGIN)
char BCPKG_21_DATA[BCPKG_21_SIZE];
char PKG21_DATA[PKG21_SIZE];

//These are variable, so they are defined later
char* TZ_DATA = NULL;
int TZ_SIZE;

char ZERO_KEY[0x100] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


//These are the names of keys we have to pull out individually
char KEY_NAMES[0x13][32] = {
	"secure_boot_key",                      //Key 0x00
	"tsec_key",                             //Key 0x01
	"keyblob_mac_key_source\0",             //Key 0x02
	"keyblob_key_source_00\0",              //Key 0x03
	"master_key_source\0",                  //Key 0x04
	"package2_key_source\0",                //Key 0x05
	"aes_kek_generation_source\0",          //Key 0x06
	"aes_key_generation_source\0",          //Key 0x07
	"titlekek_source\0",                    //Key 0x08
	"key_area_key_application_source\0",    //Key 0x09
	"key_area_key_ocean_source\0",          //Key 0x0A
	"key_area_key_system_source\0",         //Key 0x0B
	"sd_card_kek_source\0",                 //Key 0x0C
	"sd_card_save_key_source\0",            //Key 0x0D
	"sd_card_nca_key_source\0",             //Key 0x0E
	"header_kek_source\0",                  //Key 0x0F
	"header_key_source\0",                  //Key 0x10
	"encrypted_header_key\0",               //Key 0x11
	"header_key\0"                          //Key 0x12
};

int KEY_SIZES[0x13] = {
	0x10,                                   //Key 0x00 : secure_boot_key
	0x10,                                   //Key 0x01 : tsec_key
	0x10,                                   //Key 0x02 : keyblob_mac_key_source
	0x10,                                   //Key 0x03 : keyblob_key_source_00
	0x10,                                   //Key 0x04 : master_key_source
	0x10,                                   //Key 0x05 : package2_key_source
	0x10,                                   //Key 0x06 : aes_kek_generation_source
	0x10,                                   //Key 0x07 : aes_key_generation_source
	0x10,                                   //Key 0x08 : titlekek_source
	0x10,                                   //Key 0x09 : key_area_key_application_source
	0x10,                                   //Key 0x0A : key_area_key_ocean_source
	0x10,                                   //Key 0x0B : key_area_key_system_source
	0x10,                                   //Key 0x0C : sd_card_kek_source
	0x20,                                   //Key 0x0D : sd_card_save_key_source
	0x20,                                   //Key 0x0E : sd_card_nca_key_source
	0x10,                                   //Key 0x0F : header_kek_source
	0x20,                                   //Key 0x10 : header_key_source
	0x20,                                   //Key 0x11 : encrypted_header_key
	0x20                                    //Key 0x12 : header_key
};

//These are the names of keys we get in sets, ie master_key_xx
char KEYSET_NAMES[0x0B][32] = {
	"keyblob_key_source_\0",                //Keyset 0x00
	"keyblob_key_\0",                       //Keyset 0x01
	"keyblob_mac_key_\0",                   //Keyset 0x02
	"keyblob_\0",                           //Keyset 0x03
	"master_key_\0",                        //Keyset 0x04
	"package1_key_\0",                      //Keyset 0x05
	"package2_key_\0",                      //Keyset 0x06
	"titlekek_\0",                          //Keyset 0x07
	"key_area_key_application_\0",          //Keyset 0x08
	"key_area_key_ocean_\0",                //Keyset 0x09
	"key_area_key_system_\0"                //Keyset 0x0A
};

int KEYSET_SIZES[0x0B] = {
	0x10,                                   //Key 0x00 : keyblob_key_source_
	0x10,                                   //Key 0x01 : keyblob_key_
	0x10,                                   //Key 0x02 : keyblob_mac_key_
	0x90,                                   //Key 0x03 : keyblob_
	0x10,                                   //Key 0x04 : master_key_
	0x10,                                   //Key 0x05 : package1_key_
	0x10,                                   //Key 0x06 : package2_key_
	0x10,                                   //Key 0x07 : titlekek_
	0x10,                                   //Key 0x08 : key_area_key_application_
	0x10,                                   //Key 0x09 : key_area_key_ocean_
	0x10,                                   //Key 0x0A : key_area_key_system_
};

char KEY_HASHES[0x13][32] = {
	"",                                                                                                                           //Dummy Hash 0x00 : Key 0x00 : secure_boot_key
	"",                                                                                                                           //Dummy Hash 0x01 : Key 0x01 : tsec_key
	"\xB2\x4B\xD2\x93\x25\x9D\xBC\x7A\xC5\xD6\x3F\x88\xE6\x0C\x59\x79\x24\x98\xE6\xFC\x54\x43\x40\x2C\x7F\xFE\x87\xEE\x8B\x61\xA3\xF0", //Hash 0x00 : Key 0x02 : keyblob_mac_key_source
	"\x8A\x06\xFE\x27\x4A\xC4\x91\x43\x67\x91\xFD\xB3\x88\xBC\xDD\x3A\xB9\x94\x3B\xD4\xDE\xF8\x09\x44\x18\xCD\xAC\x15\x0F\xD7\x37\x86", //Hash 0x01 : Key 0x03 : keyblob_key_source_00
	"\x79\x44\x86\x2A\x3A\x5C\x31\xC6\x72\x05\x95\xEF\xD3\x02\x24\x5A\xBD\x1B\x54\xCC\xDC\xF3\x30\x00\x55\x76\x81\xE6\x5C\x56\x64\xA4", //Hash 0x02 : Key 0x04 : master_key_source
	"\x21\xE2\xDF\x10\x0F\xC9\xE0\x94\xDB\x51\xB4\x7B\x9B\x1D\x6E\x94\xED\x37\x9D\xB8\xB5\x47\x95\x5B\xEF\x8F\xE0\x8D\x8D\xD3\x56\x03", //Hash 0x03 : Key 0x05 : package2_key_source
	"\xFC\x02\xB9\xD3\x7B\x42\xD7\xA1\x45\x2E\x71\x44\x4F\x1F\x70\x03\x11\xD1\x13\x2E\x30\x1A\x83\xB1\x60\x62\xE7\x2A\x78\x17\x50\x85", //Hash 0x04 : Key 0x06 : aes_kek_generation_source
	"\xFB\xD1\x00\x56\x99\x9E\xDC\x7A\xCD\xB9\x60\x98\xE4\x7E\x2C\x36\x06\x23\x02\x70\xD2\x32\x81\xE6\x71\xF0\xF3\x89\xFC\x5B\xC5\x85", //Hash 0x05 : Key 0x07 : aes_key_generation_source
	"\xC4\x8B\x61\x98\x27\x98\x6C\x7F\x4E\x30\x81\xD5\x9D\xB2\xB4\x60\xC8\x43\x12\x65\x0E\x9A\x8E\x6B\x45\x8E\x53\xE8\xCB\xCA\x4E\x87", //Hash 0x06 : Key 0x08 : titlekek_source
	"\x04\xAD\x66\x14\x3C\x72\x6B\x2A\x13\x9F\xB6\xB2\x11\x28\xB4\x6F\x56\xC5\x53\xB2\xB3\x88\x71\x10\x30\x42\x98\xD8\xD0\x09\x2D\x9E", //Hash 0x07 : Key 0x09 : key_area_key_application_source
	"\xFD\x43\x40\x00\xC8\xFF\x2B\x26\xF8\xE9\xA9\xD2\xD2\xC1\x2F\x6B\xE5\x77\x3C\xBB\x9D\xC8\x63\x00\xE1\xBD\x99\xF8\xEA\x33\xA4\x17", //Hash 0x08 : Key 0x0A : key_area_key_ocean_source
	"\x1F\x17\xB1\xFD\x51\xAD\x1C\x23\x79\xB5\x8F\x15\x2C\xA4\x91\x2E\xC2\x10\x64\x41\xE5\x17\x22\xF3\x87\x00\xD5\x93\x7A\x11\x62\xF7", //Hash 0x09 : Key 0x0B : key_area_key_system_source
	"\x6B\x2E\xD8\x77\xC2\xC5\x23\x34\xAC\x51\xE5\x9A\xBF\xA7\xEC\x45\x7F\x4A\x7D\x01\xE4\x62\x91\xE9\xF2\xEA\xA4\x5F\x01\x1D\x24\xB7", //Hash 0x0C : Key 0x0C : sd_card_kek_source
	"\xD4\x82\x74\x35\x63\xD3\xEA\x5D\xCD\xC3\xB7\x4E\x97\xC9\xAC\x8A\x34\x21\x64\xFA\x04\x1A\x1D\xC8\x0F\x17\xF6\xD3\x1E\x4B\xC0\x1C", //Hash 0x0D : Key 0x0D : sd_card_save_key_source
	"\x2E\x75\x1C\xEC\xF7\xD9\x3A\x2B\x95\x7B\xD5\xFF\xCB\x08\x2F\xD0\x38\xCC\x28\x53\x21\x9D\xD3\x09\x2C\x6D\xAB\x98\x38\xF5\xA7\xCC", //Hash 0x0E : Key 0x0E : sd_card_nca_key_source
	"\x18\x88\xCA\xED\x55\x51\xB3\xED\xE0\x14\x99\xE8\x7C\xE0\xD8\x68\x27\xF8\x08\x20\xEF\xB2\x75\x92\x10\x55\xAA\x4E\x2A\xBD\xFF\xC2", //Hash 0x0F : Key 0x0F : header_kek_source
	"\x8F\x78\x3E\x46\x85\x2D\xF6\xBE\x0B\xA4\xE1\x92\x73\xC4\xAD\xBA\xEE\x16\x38\x00\x43\xE1\xB8\xC4\x18\xC4\x08\x9A\x8B\xD6\x4A\xA6", //Hash 0x10 : Key 0x10 : header_key_source
	"",                                                                                                                           //Dummy Hash 0x00 : Key 0x11 : encrypted_header_key
	""                                                                                                                            //Dummy Hash 0x00 : Key 0x12 : header_key
};


//Credit for these goes to SciresM (https://raw.githubusercontent.com/Atmosphere-NX/Atmosphere/master/fusee/fusee-secondary/src/key_derivation.c)
//but credit for the idea to use them goes to @Stay off my cock#6239 (nickname Shadów) on the reswitched Discord
//As of right now, only 0 - 4 are used but there will be more in future firmwares
char KEYBLOB_SEEDS[0x20][0x10] = {
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x0C\x25\x61\x5D\x68\x4C\xEB\x42\x1C\x23\x79\xEA\x82\x25\x12\xAC",
	"\x33\x76\x85\xEE\x88\x4A\xAE\x0A\xC2\x8A\xFD\x7D\x63\xC0\x43\x3B",
	"\x2D\x1F\x48\x80\xED\xEC\xED\x3E\x3C\xF2\x48\xB5\x65\x7D\xF7\xBE",
	"\xBB\x5A\x01\xF9\x88\xAF\xF5\xFC\x6C\xFF\x07\x9E\x13\x3C\x39\x80",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
};

char keyfilepath[28] = "/switch/kezplez-nx/keys.txt\0";

int appstate, progress, step_result, fail_result;
FILE* keyfile;
bool step_completed;
Thread* step_thread;

u32 read_i32_le(FILE* targetfile)
{
	u8 buf[4];
	fread(buf, 4, 1, targetfile);
	return (buf[3] << 24) + (buf[2] << 16) + (buf[1] << 8) + (buf[0]);
}

void bedug_print(char* print_text)
{
	FILE* dbg_f = fopen("/switch/kezplez-nx/ini1/debug.txt", "a+b");
	
	fwrite(print_text, strlen(print_text), 1, dbg_f);
	
	fflush(dbg_f);
	fclose(dbg_f);
}

//so it turns out I do have to know how to do this now
char* blz_decompress(FILE* has_compdata, u32 compdata_off, u32 compdata_size, int* decompdata_size)
{
	//char debugbuf[256];
	
	//sprintf(debugbuf, "reading compressed data into memory...\n");
	//bedug_print(debugbuf);
	u8* compressed = malloc(compdata_size);
	fseek(has_compdata, compdata_off, SEEK_SET);
	fread(compressed, compdata_size, 1, has_compdata);
	
	int total = compdata_off + compdata_size - 0x0C;
	//sprintf(debugbuf, "obtaining info about compressed data...\n");
	//bedug_print(debugbuf);
	//sprintf(debugbuf, "compdata_off:%08x, compdata_size:%08x, total:%08x\n", compdata_off, compdata_size, total);
	//bedug_print(debugbuf);
	fseek(has_compdata, 0, SEEK_SET);
	fseek(has_compdata, total, SEEK_SET);
	//int loc = ftell(has_compdata);
	//sprintf(debugbuf, "loc:%08x\n", loc);
	//bedug_print(debugbuf);
	u32 compressed_size = read_i32_le(has_compdata);
	u32 init_index = read_i32_le(has_compdata);
	u32 uncompressed_addl_size = read_i32_le(has_compdata);
	//loc = ftell(has_compdata);
	//sprintf(debugbuf, "loc:%08x\n", loc);
	//bedug_print(debugbuf);
	//sprintf(debugbuf, "compressed_size:%08x, init_index:%08x, uncompressed_addl_size:%08x\n", compressed_size, init_index, uncompressed_addl_size);
	//bedug_print(debugbuf);
	
	//sprintf(debugbuf, "creating decompression buffer...\n");
	//bedug_print(debugbuf);
	int decompressed_size = compressed_size + uncompressed_addl_size;
	*decompdata_size = decompressed_size;
	char* decompressed = malloc(decompressed_size);
	if (compdata_size != compressed_size)
	{
		memcpy(decompressed, compressed + (compdata_size - compressed_size), compressed_size);
	}
	else
	{
		memcpy(decompressed, compressed, compressed_size);
	}
	
	int index = compressed_size - init_index;
	int outindex = decompressed_size;
	//sprintf(debugbuf, "decompressing...\n");
	//bedug_print(debugbuf);
	while (outindex > 0)
	{
		index--;
		u8 control = (u8) compressed[index];
		for (int i = 0; i < 8; i++)
		{
			if (control & 0x80)
			{
				if (index < 2) { }//sprintf(debugbuf, "ERR: Compression out of bounds! (case 0)\n"); bedug_print(debugbuf); }
				index -= 2;
				int segmentoffset = compressed[index] | (compressed[index + 1] << 8);
				int segmentsize = ((segmentoffset >> 12) & 0xF) + 3;
				segmentoffset = segmentoffset & 0x0FFF;
				segmentoffset += 2;
				if (outindex < segmentsize) { }//sprintf(debugbuf, "ERR: Compression out of bounds! (case 1)\n"); bedug_print(debugbuf); }
				for (int j = 0; j < segmentsize; j++)
				{
					if (outindex + segmentoffset >= decompressed_size) { }//sprintf(debugbuf, "ERR: Compression out of bounds! (case 2)\n"); bedug_print(debugbuf); }
					char data = decompressed[outindex + segmentoffset];
					outindex--;
					decompressed[outindex] = data;
				}
			}
			else
			{
				if (outindex < 1) { }//sprintf(debugbuf, "ERR: Compression out of bounds! (case 3)\n"); bedug_print(debugbuf); }
				outindex--;
				index--;
				decompressed[outindex] = compressed[index];
			}
			control = control << 1;
			control = control & 0xFF;
			if (outindex == 0)
			{
				break;
			}
		}
	}
	
	return decompressed;
}

char* kip_get_full(FILE* kipfile, int* kipsize)
{
	//char debugbuf[256];
	//FILE* dbg_f = fopen("/switch/kezplez-nx/ini1/debug.txt", "wb");
	//fclose(dbg_f);
	
	//sprintf(debugbuf, "reading sizes...\n");
	//bedug_print(debugbuf);
	fseek(kipfile, 0x28, SEEK_SET);
	/*u32 tloc = read_i32_le(kipfile); u32 tsize = read_i32_le(kipfile);*/ u32 tfilesize = read_i32_le(kipfile);
	//sprintf(debugbuf, "tloc: %08x, tsize: %08x, tfilesize: %08x\n", tloc, tsize, tfilesize);
	//bedug_print(debugbuf);
	fseek(kipfile, 0x38, SEEK_SET);
	/*u32 rloc = read_i32_le(kipfile); u32 rsize = read_i32_le(kipfile);*/ u32 rfilesize = read_i32_le(kipfile);
	//sprintf(debugbuf, "rloc: %08x, rsize: %08x, rfilesize: %08x\n", rloc, rsize, rfilesize);
	//bedug_print(debugbuf);
	fseek(kipfile, 0x48, SEEK_SET);
	/*u32 dloc = read_i32_le(kipfile); u32 dsize = read_i32_le(kipfile);*/ u32 dfilesize = read_i32_le(kipfile);
	//sprintf(debugbuf, "dloc: %08x, dsize: %08x, dfilesize: %08x\n", dloc, dsize, dfilesize);
	//bedug_print(debugbuf);

	int toff = 0x100;
	int roff = toff + tfilesize;
	int doff = roff + rfilesize;
	//sprintf(debugbuf, "toff: %08x, roff: %08x, doff: %08x\n", toff, roff, doff);
	//bedug_print(debugbuf);

	//fseek(kipfile, 0x18, SEEK_SET);
	//int bsssize = read_i32_le(kipfile);
	//sprintf(debugbuf, "bss-size: %08x\n", bsssize);
	//bedug_print(debugbuf);

	int t_dsize, r_dsize, d_dsize;
	//sprintf(debugbuf, "decompressing sections (t)...\n");
	//bedug_print(debugbuf);
	char* text = blz_decompress(kipfile, toff, tfilesize, &t_dsize);
	//sprintf(debugbuf, "decompressing sections (r)...\n");
	//bedug_print(debugbuf);
	char* ro   = blz_decompress(kipfile, roff, rfilesize, &r_dsize);
	//sprintf(debugbuf, "decompressing sections (d)...\n");
	//bedug_print(debugbuf);
	char* data = blz_decompress(kipfile, doff, dfilesize, &d_dsize);
	
	
	//sprintf(debugbuf, "joining sections...\n");
	//bedug_print(debugbuf);
	char* full = malloc(t_dsize + r_dsize + d_dsize);
	
	memcpy(full, text, t_dsize);
	memcpy(full + t_dsize, ro, r_dsize);
	memcpy(full + t_dsize + r_dsize, data, d_dsize);
	
	//sprintf(debugbuf, "cleaning up...\n");
	//bedug_print(debugbuf);
	free(text); free(ro); free(data);
	*kipsize = t_dsize + r_dsize + d_dsize;
	
	return full;
}


//hactool-based definitions
hactool_ctx_t tool_ctx;
nca_ctx_t nca_ctx;

//ALWAYS USE free(); on the pointers returned by find_via_hash and hex_of_key!!
char* find_via_hash(char* data, char* keyhash, int keysize, int datasize)
{
	unsigned char rawkey[keysize];
	char* hexkey = malloc(keysize * 2);
	unsigned char digest[32];
	
	for (int i = 0; i < (datasize - keysize); i++)
	{
		memcpy(rawkey, data + i, keysize);
		mbedtls_sha256_ret(rawkey, keysize, digest, 0);
		if (strncmp((char*) digest, keyhash, 32) == 0)
		{
			for (int j = 0; j < keysize; j++)
			{
				sprintf(hexkey + (j * 2), "%02x", rawkey[j]);
			}
			return hexkey;
		}
	}
	
	memcpy(hexkey, "nokey\0", 6);
	return hexkey;
}

char* hex_of_key(char* rawkey, int keysize)
{
	char* hexkey = malloc(keysize * 2);
	for (int j = 0; j < keysize; j++)
	{
		sprintf(hexkey + (j * 2), "%02x", rawkey[j]);
	}
	return hexkey;
}

void safe_open_key_file()
{
	keyfile = fopen(keyfilepath, "r+b");
	if (keyfile == NULL)
	{
		keyfile = fopen(keyfilepath, "wb");
		fclose(keyfile);
		keyfile = fopen(keyfilepath, "r+b");
	}
}

void add_to_key_file(char* keyname, char* keycontent)
{
	keyfile = fopen(keyfilepath, "a+");
	
	fwrite(keyname, strlen(keyname), 1, keyfile);
	fwrite(" = ", 3, 1, keyfile);
	fwrite(keycontent, strlen(keycontent), 1, keyfile);
	fwrite("\n", 1, 1, keyfile);
	fflush(keyfile);
	
	fclose(keyfile);
}

void add_to_key_file_no_open(char* keyname, char* keycontent)
{
	fwrite(keyname, strlen(keyname), 1, keyfile);
	fwrite(" = ", 3, 1, keyfile);
	fwrite(keycontent, strlen(keycontent), 1, keyfile);
	fwrite("\n", 1, 1, keyfile);
}

void add_to_key_file_sized(char* keyname, char* keycontent, int keysize)
{
	fwrite(keyname, strlen(keyname), 1, keyfile);
	fwrite(" = ", 3, 1, keyfile);
	fwrite(keycontent, keysize * 2, 1, keyfile);
	fwrite("\n", 1, 1, keyfile);
}

//for use with keysets
void add_to_key_file_sized_indexed(char* keyname, char* keycontent, int keysize, int keyindex)
{
	keyindex = keyindex & 0xff; //precaution
	
	char keyname_indexed[strlen(keyname) + 3];
	strcpy(keyname_indexed, keyname);
	sprintf(keyname_indexed + strlen(keyname), "%02x", keyindex);
	keyname_indexed[strlen(keyname) + 2] = 0x00;
	
	add_to_key_file_sized(keyname_indexed, keycontent, keysize);
}

void find_and_add_key(char* data, int keyid, int datasize)
{
	char* key = find_via_hash(data, KEY_HASHES[keyid], KEY_SIZES[keyid], datasize);
	add_to_key_file(KEY_NAMES[keyid], key);
	free(key);
}

void add_keyset(char** keyset_array, int keyset_id)
{
	int keyset_size = KEYSET_SIZES[keyset_id];
	char* keyset_name = KEYSET_NAMES[keyset_id];
	char* hexkey;
	char real_keyset_array[0x20][keyset_size];
	memcpy(real_keyset_array, keyset_array, 0x20 * keyset_size);
	
	for(int i = 0; i < 0x20; i++)
	{
		if (memcmp(real_keyset_array[i], ZERO_KEY, keyset_size) == 0) { continue; }
		
		hexkey = hex_of_key(real_keyset_array[i], keyset_size);
		add_to_key_file_sized_indexed(keyset_name, hexkey, keyset_size, i);
		free(hexkey);
	}
}

void add_keyset_key_area(char** keyset_key_area_array, int keyset_id, int key_area_id)
{
	int keyset_size = KEYSET_SIZES[keyset_id];
	char* keyset_name = KEYSET_NAMES[keyset_id];
	char* hexkey;
	char real_keyset_array[0x20][0x3][keyset_size];
	memcpy(real_keyset_array, keyset_key_area_array, 0x20 * 0x3 * keyset_size);
	
	for(int i = 0; i < 0x20; i++)
	{
		if (memcmp(real_keyset_array[i][key_area_id], ZERO_KEY, keyset_size) == 0) { continue; }
		
		hexkey = hex_of_key(real_keyset_array[i][key_area_id], keyset_size);
		add_to_key_file_sized_indexed(keyset_name, hexkey, keyset_size, i);
		free(hexkey);
	}
}

void update_keyfile(int stage, nca_keyset_t* keyset)
{
	keyfile = fopen(keyfilepath, "a+");
	char* hexkey;
	
	if (stage == 0)
	{
		//keyblob_key_xx
		add_keyset((char**) keyset->keyblob_keys, 0x01);
		
		//keyblob_mac_key_xx
		add_keyset((char**) keyset->keyblob_mac_keys, 0x02);
		
		//keyblob_xx
		add_keyset((char**) keyset->keyblobs, 0x03);
		
		//master_key_xx
		add_keyset((char**) keyset->master_keys, 0x04);
		
		//package1_key_xx
		add_keyset((char**) keyset->package1_keys, 0x05);
	}
	
	if (stage == 1)
	{
		//package2_key_xx
		add_keyset((char**) keyset->package2_keys, 0x06);
		
		//titlekek_xx
		add_keyset((char**) keyset->titlekeks, 0x07);
	}
	
	if (stage == 2)
	{
		//encrypted_header_key
		hexkey = hex_of_key((char*) keyset->encrypted_header_key, KEY_SIZES[0x11]);
		add_to_key_file_sized(KEY_NAMES[0x11], hexkey, KEY_SIZES[0x11]);
		free(hexkey);
		
		//header_key
		hexkey = hex_of_key((char*) keyset->header_key, KEY_SIZES[0x12]);
		add_to_key_file_sized(KEY_NAMES[0x12], hexkey, KEY_SIZES[0x12]);
		free(hexkey);
		
		//key_area_key_application_xx
		add_keyset_key_area((char**) keyset->key_area_keys, 0x08, 0x00);
		
		//key_area_key_ocean_xx
		add_keyset_key_area((char**) keyset->key_area_keys, 0x09, 0x01);
		
		//key_area_key_system_xx
		add_keyset_key_area((char**) keyset->key_area_keys, 0x0A, 0x02);
	}
	
	fflush(keyfile);
	fclose(keyfile);
}

void get_tsec_sbk()
{
	safe_open_key_file();
	
	char sbk[0x10];
	char tsec_key[0x10];
	char* hexkey;
	
	FILE* fusefile = fopen("/Backup/Dumps/fuses.bin", "rb");
	FILE* tsecfile = fopen("/Backup/Dumps/tsec_key.bin", "rb");
	
	fseek(fusefile, 0, SEEK_SET);
	fseek(fusefile, 0xA4, SEEK_SET);
	fseek(tsecfile, 0, SEEK_SET);
	
	fread(sbk, 0x10, 1, fusefile);
	fread(tsec_key, 0x10, 1, tsecfile);
	
	hexkey = hex_of_key(sbk, KEY_SIZES[0x00]);
	add_to_key_file_sized(KEY_NAMES[0x00], hexkey, KEY_SIZES[0x00]);
	free(hexkey);
	hexkey = hex_of_key(tsec_key, KEY_SIZES[0x01]);
	add_to_key_file_sized(KEY_NAMES[0x01], hexkey, KEY_SIZES[0x01]);
	free(hexkey);
	
	fclose(fusefile);
	fclose(tsecfile);
	
	fclose(keyfile);
}

void hactool_init()
{
	memset(&tool_ctx, 0, sizeof(tool_ctx));
	tool_ctx.action = ACTION_INFO | ACTION_EXTRACT;
	// key init
	safe_open_key_file();
	
	pki_initialize_keyset(&tool_ctx.settings.keyset, KEYSET_RETAIL);
	extkeys_initialize_keyset(&tool_ctx.settings.keyset, keyfile);
	
	nca_ctx.tool_ctx = &tool_ctx;
	
	pki_derive_keys(&tool_ctx.settings.keyset);
	fclose(keyfile);
}

void dump_bis_partition(char* filepath, u32 partition_id)
{
	step_completed = false;
	
	FILE* dumpfile = fopen(filepath, "wb");
	FsStorage partition;
	u64 partition_size, dump_progress, bytes_to_dump;
	
	Result rc = fsOpenBisStorage(&partition, partition_id);
	if (R_FAILED(rc)) { fail_result = rc; step_completed = true; return; }
	
	rc = fsStorageGetSize(&partition, &partition_size);
	if (R_FAILED(rc)) { fail_result = rc; step_completed = true; return; }
	
	size_t dump_buffer_size = 0x10000;
	u8 dump_buffer[dump_buffer_size];
	
	dump_progress = 0;
	while(dump_progress < partition_size)
	{
		if ((partition_size - dump_progress) > dump_buffer_size)
		{
			bytes_to_dump = dump_buffer_size;
		}
		else
		{
			bytes_to_dump = (partition_size - dump_progress);
		}
		
		rc = fsStorageRead(&partition, dump_progress, dump_buffer, bytes_to_dump);
		if (R_FAILED(rc)) { fail_result = rc; step_completed = true; return; }
		
		fwrite(dump_buffer, bytes_to_dump, 1, dumpfile);
		
		dump_progress += bytes_to_dump;
	}
	
	fsStorageClose(&partition);
	fclose(dumpfile);
	
	step_completed = true;
	step_result = rc;
}

void dump_boot0()
{
	dump_bis_partition("/switch/kezplez-nx/boot0.bin", 0);
}

void dump_bcpkg_21()
{
	dump_bis_partition("/switch/kezplez-nx/BCPKG_21_NormalMain.bin", 21);
}

void extract_package2()
{
	step_completed = false;
	
	FILE* BCPKG_21_f = fopen("/switch/kezplez-nx/BCPKG_21_NormalMain.bin", "rb");
	FILE* PKG21_f = fopen("/switch/kezplez-nx/package2.bin", "wb");
	
	fread(BCPKG_21_DATA, BCPKG_21_SIZE, 1, BCPKG_21_f);
	memcpy(PKG21_DATA, BCPKG_21_DATA + PKG21_BEGIN, PKG21_SIZE);
	fwrite(PKG21_DATA, PKG21_SIZE, 1, PKG21_f);
	
	fclose(PKG21_f);
	fclose(BCPKG_21_f);
	
	step_completed = true;
	step_result = 0;
}

void extract_package1_encrypted()
{
	step_completed = false;
	
	FILE* BOOT0_f = fopen("/switch/kezplez-nx/boot0.bin", "rb");
	FILE* PKG11_f = fopen("/switch/kezplez-nx/package1.bin", "wb");
	
	fread(BOOT0_DATA, BOOT0_SIZE, 1, BOOT0_f);
	
	char* PKG11_SEARCH_BEGIN = BOOT0_DATA + 0x100000;
	char* PKG11_SEARCH_END = BOOT0_DATA + 0x140000;
	char* PKG11_SEARCH_POS = PKG11_SEARCH_BEGIN;
	u32 PKG11_TARGET_STR_BE = 0x504B3131;
	u32 PKG11_TARGET_STR_LE = 0x31314B50;
	
	for (; PKG11_SEARCH_POS < PKG11_SEARCH_END; PKG11_SEARCH_POS += 4)
	{
		u32 PKG11_TARGET_TEST = *((u32*) PKG11_SEARCH_POS);
		if (PKG11_TARGET_TEST == PKG11_TARGET_STR_BE || PKG11_TARGET_TEST == PKG11_TARGET_STR_LE)
		{
			PKG11_LOC = PKG11_SEARCH_POS;
			break;
		}
	}
	memcpy(PKG11_DATA, PKG11_LOC, PKG11_SIZE);
	fwrite(PKG11_DATA, PKG11_SIZE, 1, PKG11_f);
	
	fclose(PKG11_f);
	fclose(BOOT0_f);
	
	step_completed = true;
	step_result = 0;
}

void derive_part0a()
{
	step_completed = false;
	
	find_and_add_key(PKG11_DATA, 0x02, PKG11_SIZE);  //keyblob_mac_key_source
	
	step_completed = true;
	step_result = 0;
}

void derive_part0b()
{
	step_completed = false;
	
	find_and_add_key(PKG11_DATA, 0x03, PKG11_SIZE);  //keyblob_key_source_00
	
	step_completed = true;
	step_result = 0;
}

void derive_part0c()
{
	step_completed = false;
	
	find_and_add_key(PKG11_DATA, 0x04, PKG11_SIZE);  //master_key_source
	
	step_completed = true;
	step_result = 0;
}

void add_other_keyblob_seeds()
{
	step_completed = false;
	
	keyfile = fopen(keyfilepath, "a+");
	
	add_keyset((char**) KEYBLOB_SEEDS, 0x00);
	
	fflush(keyfile);
	fclose(keyfile);
	
	step_completed = true;
	step_result = 0;
}

void extract_package1_encrypted_butagain()
{
	step_completed = false;
	
	FILE* BOOT0_f = fopen("/switch/kezplez-nx/boot0.bin", "rb");
	FILE* PKG11_f = fopen("/switch/kezplez-nx/package1.bin", "wb");
	
	fread(BOOT0_DATA, BOOT0_SIZE, 1, BOOT0_f);
	memcpy(PKG11_DATA, BOOT0_DATA + PKG11_REALBEGIN, PKG11_SIZE);
	fwrite(PKG11_DATA, PKG11_SIZE, 1, PKG11_f);
	
	fclose(PKG11_f);
	fclose(BOOT0_f);
	
	step_completed = true;
	step_result = 0;
}

void decrypt_package1()
{
	step_completed = false;
	
	hactool_init();
	tool_ctx.file = fopen("/switch/kezplez-nx/boot0.bin", "r+b");
	
	nca_keyset_t new_keyset;
	memcpy(&new_keyset, &tool_ctx.settings.keyset, sizeof(new_keyset));
	for (unsigned int i = 0; i < 0x10; i++) {
		if (tool_ctx.settings.keygen_sbk[i] != 0) {
			memcpy(new_keyset.secure_boot_key, tool_ctx.settings.keygen_sbk, 0x10);
		}
	}
	for (unsigned int i = 0; i < 0x10; i++) {
		if (tool_ctx.settings.keygen_tsec[i] != 0) {
			memcpy(new_keyset.tsec_key, tool_ctx.settings.keygen_tsec, 0x10);
		}
	}
	for (unsigned int i = 0; tool_ctx.file != NULL && i < 0x20; i++) {
		fseek(tool_ctx.file, 0x180000 + 0x200 * i, SEEK_SET);
		fread(&new_keyset.encrypted_keyblobs[i], sizeof(new_keyset.encrypted_keyblobs[i]), 1, tool_ctx.file);
	}
	
	pki_derive_keys(&new_keyset);
	update_keyfile(0, &new_keyset);
	
	fclose(tool_ctx.file);
	
	hactool_init();
	FILE* pkg11_f = fopen("/switch/kezplez-nx/package1.bin", "rb");
	tool_ctx.file_type = FILETYPE_PACKAGE1;
	filepath_set(&tool_ctx.settings.pk11_dir_path, "/switch/kezplez-nx/package1\0");
	
	pk11_ctx_t pk11_ctx;
	memset(&pk11_ctx, 0, sizeof(pk11_ctx));
	pk11_ctx.file = tool_ctx.file;
	pk11_ctx.tool_ctx = &tool_ctx;
	tool_ctx.file = pkg11_f;
	pk11_ctx.file = pkg11_f;
	pk11_process(&pk11_ctx);
	
	if (pk11_ctx.pk11) {
		free(pk11_ctx.pk11);
	}
	
	// char failure[5]; failure[4] = 0x00;
	// snprintf(failure, 4, "%02x", pk11_process(&pk11_ctx));
	
	// add_to_key_file("failure?", failure);
	
	fclose(tool_ctx.file);
	
	step_result = 0;
	step_completed = true;
}

void derive_part1a()
{
	step_completed = false;
	
	FILE* TZ_f = fopen("/switch/kezplez-nx/package1/Secure_Monitor.bin", "rb");
	
	fseek(TZ_f, 0, SEEK_END);
	TZ_SIZE = ftell(TZ_f);
	fseek(TZ_f, 0, SEEK_SET);
	
	TZ_DATA = malloc(TZ_SIZE);
	fread(TZ_DATA, TZ_SIZE, 1, TZ_f);
	fclose(TZ_f);
	
	find_and_add_key(TZ_DATA, 0x05, TZ_SIZE);  //package2_key_source
	
	step_result = 0;
	step_completed = true;
}

void derive_part1b()
{
	step_completed = false;
	
	find_and_add_key(TZ_DATA, 0x06, TZ_SIZE);  //aes_kek_generation_source
	
	step_result = 0;
	step_completed = true;
}

void derive_part1c()
{
	step_completed = false;
	
	find_and_add_key(TZ_DATA, 0x08, TZ_SIZE);  //titlekek_source
	
	step_result = 0;
	step_completed = true;
}

void extract_package2_contents()
{
	step_completed = false;
	
	hactool_init();
	pki_derive_keys(&tool_ctx.settings.keyset);
	update_keyfile(1, &tool_ctx.settings.keyset);
	
	hactool_init();
	
	tool_ctx.file = fopen("/switch/kezplez-nx/package2.bin", "rb");
	tool_ctx.file_type = FILETYPE_PACKAGE2;
	filepath_set(&tool_ctx.settings.pk21_dir_path, "/switch/kezplez-nx/package2\0");
	filepath_set(&tool_ctx.settings.ini1_dir_path, "/switch/kezplez-nx/ini1\0");
	
	pk21_ctx_t pk21_ctx;
	memset(&pk21_ctx, 0, sizeof(pk21_ctx));
	pk21_ctx.file = tool_ctx.file;
	pk21_ctx.tool_ctx = &tool_ctx;
	pk21_process(&pk21_ctx);
	if (pk21_ctx.sections) {
		free(pk21_ctx.sections);
	}
	
	fclose(tool_ctx.file);
	
	step_result = 0;
	step_completed = true;
}

void extract_kip1s()
{
	step_completed = false;
	
	FILE* spl_f = fopen("/switch/kezplez-nx/ini1/spl.kip1\0", "rb");
	FILE* decomp_spl_f = fopen("/switch/kezplez-nx/ini1/decomp_spl.kip1\0", "wb");
	int spl_size;
	char* spl_data = kip_get_full(spl_f, &spl_size);
	fwrite(spl_data, spl_size, 1, decomp_spl_f);
	
	free(spl_data);
	fclose(decomp_spl_f);
	fclose(spl_f);
	
	FILE* FS_f = fopen("/switch/kezplez-nx/ini1/FS.kip1\0", "rb");
	FILE* decomp_FS_f = fopen("/switch/kezplez-nx/ini1/decomp_FS.kip1\0", "wb");
	int FS_size;
	char* FS_data = kip_get_full(FS_f, &FS_size);
	fwrite(FS_data, FS_size, 1, decomp_FS_f);
	
	free(FS_data);
	fclose(decomp_FS_f);
	fclose(FS_f);
	
	step_result = 0;
	step_completed = true;
}

void derive_part2_spl()
{
	step_completed = false;
	
	//fopen("/switch/kezplez-nx/ini1/spl-0\0", "wb");
	FILE* SPL_f = fopen("/switch/kezplez-nx/ini1/decomp_spl.kip1\0", "rb");
	
	//fopen("/switch/kezplez-nx/ini1/spl-1\0", "wb");
	fseek(SPL_f, 0, SEEK_END);
	int SPL_SIZE = ftell(SPL_f);
	fseek(SPL_f, 0, SEEK_SET);
	
	//fopen("/switch/kezplez-nx/ini1/spl-2\0", "wb");
	char* SPL_DATA = malloc(SPL_SIZE);
	fread(SPL_DATA, SPL_SIZE, 1, SPL_f);
	fclose(SPL_f);
	
	//fopen("/switch/kezplez-nx/ini1/spl-3\0", "wb");
	find_and_add_key(SPL_DATA, 0x07, SPL_SIZE);  //aes_key_generation_source
	
	//fopen("/switch/kezplez-nx/ini1/spl-4\0", "wb");
	free(SPL_DATA);
	
	//fopen("/switch/kezplez-nx/ini1/spl-5\0", "wb");
	step_result = 0;
	step_completed = true;
}

void derive_part2_FS()
{
	step_completed = false;
	
	FILE* FS_f = fopen("/switch/kezplez-nx/ini1/decomp_FS.kip1\0", "rb");
	
	fseek(FS_f, 0, SEEK_END);
	int FS_SIZE = ftell(FS_f);
	fseek(FS_f, 0, SEEK_SET);
	
	char* FS_DATA = malloc(FS_SIZE);
	fread(FS_DATA, FS_SIZE, 1, FS_f);
	fclose(FS_f);
	
	find_and_add_key(FS_DATA, 0x09, FS_SIZE);  //key_area_key_application_source
	find_and_add_key(FS_DATA, 0x0A, FS_SIZE);  //key_area_key_ocean_source
	find_and_add_key(FS_DATA, 0x0B, FS_SIZE);  //key_area_key_system_source
	find_and_add_key(FS_DATA, 0x0C, FS_SIZE);  //sd_card_kek_source
	find_and_add_key(FS_DATA, 0x0D, FS_SIZE);  //sd_card_save_key_source
	find_and_add_key(FS_DATA, 0x0E, FS_SIZE);  //sd_card_nca_key_source
	find_and_add_key(FS_DATA, 0x0F, FS_SIZE);  //header_kek_source
	find_and_add_key(FS_DATA, 0x10, FS_SIZE);  //header_key_source
	
	free(FS_DATA);
	
	step_result = 0;
	step_completed = true;
}

void final_derivation()
{
	step_completed = false;
	
	hactool_init();
	pki_derive_keys(&tool_ctx.settings.keyset);
	update_keyfile(2, &tool_ctx.settings.keyset);
	
	step_result = 0;
	step_completed = true;
}


int main(int argc, char** argv)
{
	//app init
	gui_init();
	// socketInitializeDefault();
	// nxlinkSetup();
	// nxlinkStdio();
	
	//internal variable inits
	appstate = 0;
	progress = 0;
	fail_result = 0;
	
	//hactool init
	get_tsec_sbk();
	hactool_init();
	
	
	while (appletMainLoop())
	{
		hidScanInput();
		u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);
		if (kDown & KEY_PLUS) break;
		
		//Beginning
		if (appstate == 0)
		{
			if (kDown & KEY_A)
			{
				appstate = 1;
				step_completed = true;
			}
		}
		
		//After every step, try the next
		if (appstate == 1 && step_completed)
		{
			if (progress > 0)
			{
				threadClose(step_thread);
				free(step_thread);
			}
			
			//check if previous step failed
			if (R_FAILED(step_result) || fail_result != 0)
			{
				appstate = 3;
				progress = step_result;
			}
			else
			{
				progress++;
			}
		}
		
		
		if (appstate == 1 && step_completed)
		{
			if (progress == 1)
			{
				step_thread = util_thread_func(dump_boot0);
			}
			
			if (progress == 2)
			{
				step_thread = util_thread_func(dump_bcpkg_21);
			}
			
			if (progress == 3)
			{
				step_thread = util_thread_func(extract_package2);
			}
			
			if (progress == 4)
			{
				step_thread = util_thread_func(extract_package1_encrypted);
			}
			
			if (progress == 5)
			{
				step_thread = util_thread_func(derive_part0a);
			}
			
			if (progress == 6)
			{
				step_thread = util_thread_func(derive_part0b);
			}
			
			if (progress == 7)
			{
				step_thread = util_thread_func(derive_part0c);
			}
			
			if (progress == 8)
			{
				step_thread = util_thread_func(add_other_keyblob_seeds);
			}
			
			if (progress == 9)
			{
				step_thread = util_thread_func(extract_package1_encrypted_butagain);
			}
			
			if (progress == 10)
			{
				step_thread = util_thread_func(decrypt_package1);
			}
			
			if (progress == 11)
			{
				step_thread = util_thread_func(derive_part1a);
			}
			
			if (progress == 12)
			{
				step_thread = util_thread_func(derive_part1b);
			}
			
			if (progress == 13)
			{
				step_thread = util_thread_func(derive_part1c);
			}
			
			if (progress == 14)
			{
				step_thread = util_thread_func(extract_package2_contents);
			}
			
			if (progress == 15)
			{
				step_thread = util_thread_func(extract_kip1s);
			}
			
			if (progress == 16)
			{
				step_thread = util_thread_func(derive_part2_spl);
			}
			
			if (progress == 17)
			{
				step_thread = util_thread_func(derive_part2_FS);
			}
			
			if (progress == 18)
			{
				step_thread = util_thread_func(final_derivation);
			}
			
			if (progress == 19)
			{
				appstate = 2;
			}
		}
		
		
		gui_beginframe();
		gui_drawframe(progress);
		gui_endframe();
	}
	
	
	// socketExit();
	gui_exit();
	
	if (TZ_DATA != NULL) { free(TZ_DATA); }
	return 0;
}