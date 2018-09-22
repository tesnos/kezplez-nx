#include "keys.h"


const char nokey[6] = "nokey\0";

const char ZERO_KEY[0x100] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

const char KEY_NAMES[0x16][32] = {
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
	"header_key\0",                         //Key 0x12
	"eticket_rsa_kek_source\0",             //Key 0x13
	"eticket_rsa_kekek_source\0",           //Key 0x14
	"eticket_rsa_kek\0"                     //Key 0x15
};

const int KEY_SIZES[0x16] = {
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
	0x20,                                   //Key 0x12 : header_key
	0x10,                                   //Key 0x13 : eticket_rsa_kek_source
	0x10,                                   //Key 0x14 : eticket_rsa_kekek_source
	0x10,                                   //Key 0x15 : eticket_rsa_kek
};

const char KEYSET_NAMES[0x0B][32] = {
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

const int KEYSET_SIZES[0x0B] = {
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

const char KEY_HASHES[0x16][32] = {
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
	"",                                                                                                                           //Dummy Hash 0x00 : Key 0x12 : header_key
	"\xB7\x1D\xB2\x71\xDC\x33\x8D\xF3\x80\xAA\x2C\x43\x35\xEF\x88\x73\xB1\xAF\xD4\x08\xE8\x0B\x35\x82\xD8\x71\x9F\xC8\x1C\x5E\x51\x1C", //Hash 0x13 : Key 0x13 : eticket_rsa_kek_source
	"\xE8\x96\x5A\x18\x7D\x30\xE5\x78\x69\xF5\x62\xD0\x43\x83\xC9\x96\xDE\x48\x7B\xBA\x57\x61\x36\x3D\x2D\x4D\x32\x39\x18\x66\xA8\x5C", //Hash 0x14 : Key 0x14 : eticket_rsa_kekek_source
	"",                                                                                                                           //Dummy Hash 0x00 : Key 0x15 : eticket_rsa_kek
};

const char KEYBLOB_SEEDS[0x20][0x10] = {
	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
	"\x0C\x25\x61\x5D\x68\x4C\xEB\x42\x1C\x23\x79\xEA\x82\x25\x12\xAC",
	"\x33\x76\x85\xEE\x88\x4A\xAE\x0A\xC2\x8A\xFD\x7D\x63\xC0\x43\x3B",
	"\x2D\x1F\x48\x80\xED\xEC\xED\x3E\x3C\xF2\x48\xB5\x65\x7D\xF7\xBE",
	"\xBB\x5A\x01\xF9\x88\xAF\xF5\xFC\x6C\xFF\x07\x9E\x13\x3C\x39\x80",
	"\xD8\xCC\xE1\x26\x6A\x35\x3F\xCC\x20\xF3\x2D\x3B\x51\x7D\xE9\xC0",
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

const char rsa_kek_seed_3[0x10] = "\xE5\x4D\x9A\x02\xF0\x4F\x5F\xA8\xAD\x76\x0A\xF6\x32\x95\x59\xBB";
const char rsa_kek_mask_0[0x10] = "\x4D\x87\x09\x86\xC4\x5D\x20\x72\x2F\xBA\x10\x53\xDA\x92\xE8\xA9";

FILE* keyfile;

char hekate_tsecdump_old_path_full[512];
char hekate_tsecdump_new_path_full[512];
char hekate_fusedump_path_full[512];


void find_via_hash(char* data, const char* keyhash, int keysize, int datasize, char* resultkey)
{
	unsigned char rawkey[keysize];
	bool foundkey = false;
	unsigned char digest[32];
	
	for (int i = 0; i < (datasize - keysize); i++)
	{
		memcpy(rawkey, data + i, keysize);
		mbedtls_sha256_ret(rawkey, keysize, digest, 0);
		if (strncmp((char*) digest, keyhash, 32) == 0)
		{
			hex_of_key((char*) rawkey, keysize, resultkey);
			foundkey = true;
			break;
		}
	}
	
	if (!foundkey)
	{
		memcpy(resultkey, nokey, 6);
	}
}

void hex_of_key(char* rawkey, int keysize, char* resultkey)
{
	for (int i = 0; i < keysize; i++)
	{
		sprintf(resultkey + (i * 2), "%02x", rawkey[i]);
	}
}

void add_to_key_file(const char* keyname, char* keycontent)
{
	keyfile = safe_open_key_file();
	
	fwrite(keyname, strlen(keyname), 1, keyfile);
	fwrite(" = ", 3, 1, keyfile);
	fwrite(keycontent, strlen(keycontent), 1, keyfile);
	fwrite("\n", 1, 1, keyfile);
	fflush(keyfile);
	
	fclose(keyfile);
}

void add_to_key_file_no_open(const char* keyname, char* keycontent)
{
	fwrite(keyname, strlen(keyname), 1, keyfile);
	fwrite(" = ", 3, 1, keyfile);
	fwrite(keycontent, strlen(keycontent), 1, keyfile);
	fwrite("\n", 1, 1, keyfile);
}

void add_to_key_file_sized(const char* keyname, char* keycontent, int keysize)
{
	fwrite(keyname, strlen(keyname), 1, keyfile);
	fwrite(" = ", 3, 1, keyfile);
	fwrite(keycontent, keysize * 2, 1, keyfile);
	fwrite("\n", 1, 1, keyfile);
}

//for use with keysets
void add_to_key_file_sized_indexed(const char* keyname, char* keycontent, int keysize, int keyindex)
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
	char key[KEY_SIZES[keyid] * 2];
	find_via_hash(data, KEY_HASHES[keyid], KEY_SIZES[keyid], datasize, key);
	
	keyfile = safe_open_key_file();
	add_to_key_file_sized(KEY_NAMES[keyid], key, KEY_SIZES[keyid]);
	fflush(keyfile);
	fclose(keyfile);
}

void add_keyset(char** keyset_array, int keyset_id)
{
	int keyset_size = KEYSET_SIZES[keyset_id];
	const char* keyset_name = KEYSET_NAMES[keyset_id];
	char hexkey[keyset_size * 3];
	char real_keyset_array[0x20][keyset_size];
	memcpy(real_keyset_array, keyset_array, 0x20 * keyset_size);
	
	for(int i = 0; i < 0x20; i++)
	{
		if (memcmp(real_keyset_array[i], ZERO_KEY, keyset_size) == 0) { continue; }
		
		hex_of_key(real_keyset_array[i], keyset_size, hexkey);
		add_to_key_file_sized_indexed(keyset_name, hexkey, keyset_size, i);
	}
}

void add_keyset_key_area(char** keyset_key_area_array, int keyset_id, int key_area_id)
{
	int keyset_size = KEYSET_SIZES[keyset_id];
	const char* keyset_name = KEYSET_NAMES[keyset_id];
	char hexkey[keyset_size * 3];
	char real_keyset_array[0x20][0x3][keyset_size];
	memcpy(real_keyset_array, keyset_key_area_array, 0x20 * 0x3 * keyset_size);
	
	for(int i = 0; i < 0x20; i++)
	{
		if (memcmp(real_keyset_array[i][key_area_id], ZERO_KEY, keyset_size) == 0) { continue; }
		
		hex_of_key(real_keyset_array[i][key_area_id], keyset_size, hexkey);
		add_to_key_file_sized_indexed(keyset_name, hexkey, keyset_size, i);
	}
}

void get_tsec_sbk()
{
	keyfile = safe_open_key_file();
	
	char sbk[KEY_SIZES[0x00]];
	char tsec_key[KEY_SIZES[0x01]];
	char sbk_hex[KEY_SIZES[0x00] * 2];
	char tsec_key_hex[KEY_SIZES[0x01] * 2];
	
	debug_log("opening tsec and sbk\n");
	debug_log("old tsec path: %s, new tsec path: %s, and fuse path: %s\n", hekate_tsecdump_old_path_full, hekate_tsecdump_new_path_full, hekate_fusedump_path_full);
	FILE* tsecfile = fopen(hekate_tsecdump_old_path_full, FMODE_READ);
	if (tsecfile == NULL)
	{
		debug_log("Failed to open old tsecfile, trying newer one\n");
		tsecfile = fopen(hekate_tsecdump_new_path_full, FMODE_READ);
		if (tsecfile == NULL) { fatal_error("Failed to open tsec_key.bin or tsec_keys.bin, please make sure to dump your fuses in hekate!\n"); return; }
	}
	FILE* fusefile = fopen(hekate_fusedump_path_full, FMODE_READ);
	if (fusefile == NULL) { fatal_error("Failed to open fuses.bin, please make sure to dump your fuses in hekate!\n"); fclose(tsecfile); return; }
	
	fseek(fusefile, 0, SEEK_SET);
	fseek(fusefile, 0xA4, SEEK_SET);
	fseek(tsecfile, 0, SEEK_SET);
	
	debug_log("reading keys\n");
	fread(sbk, KEY_SIZES[0x00], 1, fusefile);
	fread(tsec_key, KEY_SIZES[0x01], 1, tsecfile);
	
	debug_log("hexlifying...\n");
	hex_of_key(sbk, KEY_SIZES[0x00], sbk_hex);
	debug_log("adding to the keyfile\n");
	add_to_key_file_sized(KEY_NAMES[0x00], sbk_hex, KEY_SIZES[0x00]);
	
	debug_log("over and over\n");
	hex_of_key(tsec_key, KEY_SIZES[0x01], tsec_key_hex);
	add_to_key_file_sized(KEY_NAMES[0x01], tsec_key_hex, KEY_SIZES[0x01]);
	
	
	debug_log("cleanup\n");
	fclose(fusefile);
	fclose(tsecfile);
	
	fclose(keyfile);
}

void update_keyfile(int stage, nca_keyset_t* keyset)
{
	keyfile = safe_open_key_file();
	
	if (stage == 0)
	{
		debug_log("Adding keyset %sxx to the key file\n", "keyblob_key_");
		add_keyset((char**) keyset->keyblob_keys, 0x01);
		
		debug_log("Adding keyset %sxx to the key file\n", "keyblob_mac_key_");
		add_keyset((char**) keyset->keyblob_mac_keys, 0x02);
		
		debug_log("Adding keyset %sxx to the key file\n", "keyblob_");
		add_keyset((char**) keyset->keyblobs, 0x03);
		
		debug_log("Adding keyset %sxx to the key file\n", "master_key_");
		add_keyset((char**) keyset->master_keys, 0x04);
		
		debug_log("Adding keyset %sxx to the key file\n", "package1_key_");
		add_keyset((char**) keyset->package1_keys, 0x05);
	}
	
	else if (stage == 1)
	{
		debug_log("Adding keyset %sxx to the key file\n", "package2_key_");
		add_keyset((char**) keyset->package2_keys, 0x06);
		
		debug_log("Adding keyset %sxx to the key file\n", "titlekek_");
		add_keyset((char**) keyset->titlekeks, 0x07);
	}
	
	else if (stage == 2)
	{
		debug_log("Adding %s to the key file\n", "encrypted_header_key");
		char encrypted_header_key_hex[KEY_SIZES[0x11] * 2];
		hex_of_key((char*) keyset->encrypted_header_key, KEY_SIZES[0x11], encrypted_header_key_hex);
		add_to_key_file_sized(KEY_NAMES[0x11], encrypted_header_key_hex, KEY_SIZES[0x11]);
		
		debug_log("Adding %s to the key file\n", "header_key");
		char header_key_hex[KEY_SIZES[0x12] * 2];
		hex_of_key((char*) keyset->header_key, KEY_SIZES[0x12], header_key_hex);
		add_to_key_file_sized(KEY_NAMES[0x12], header_key_hex, KEY_SIZES[0x12]);
		
		debug_log("Adding keyset %sxx to the key file\n", "key_area_key_application_");
		add_keyset_key_area((char**) keyset->key_area_keys, 0x08, 0x00);
		
		debug_log("Adding keyset %sxx to the key file\n", "key_area_key_ocean_");
		add_keyset_key_area((char**) keyset->key_area_keys, 0x09, 0x01);
		
		debug_log("Adding keyset %sxx to the key file\n", "key_area_key_system_");
		add_keyset_key_area((char**) keyset->key_area_keys, 0x0A, 0x02);
	}
	
	fclose(keyfile);
}