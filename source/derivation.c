#include "derivation.h"


const char secmon_path[256] = "/switch/kezplez-nx/package1/Secure_Monitor.bin\0";
const char final_keyfile_path[256] = "/prod.keys\0";


void derive_part0(application_ctx* appstate)
{
	debug_log("Getting keys from package1 code...\n");
	FILE* PKG11_f = fopen(package1_path, FMODE_READ);
	
	fseek(PKG11_f, 0, SEEK_END);
	int PKG11_TEMP_SIZE = ftell(PKG11_f);
	fseek(PKG11_f, 0, SEEK_SET);
	
	char* PKG11_DATA = malloc(PKG11_TEMP_SIZE);
	fread(PKG11_DATA, PKG11_TEMP_SIZE, 1, PKG11_f);
	fclose(PKG11_f);
	
	debug_log("Adding %s to the key file\n", "keyblob_mac_key_source");
	find_and_add_key(PKG11_DATA, 0x02, PKG11_TEMP_SIZE);  //keyblob_mac_key_source
	debug_log("Adding %s to the key file\n", "keyblob_key_source_00");
	find_and_add_key(PKG11_DATA, 0x03, PKG11_TEMP_SIZE);  //keyblob_key_source_00
	debug_log("Adding %s to the key file\n", "master_key_source");
	find_and_add_key(PKG11_DATA, 0x04, PKG11_TEMP_SIZE);  //master_key_source
	
	free(PKG11_DATA);
}

void add_other_keyblob_seeds(application_ctx* appstate)
{
	FILE* keyfile = fopen(keyfile_path, FMODE_APPEND);
	
	debug_log("Adding keyset %sxx to the key file\n", "keyblob_key_source_");
	add_keyset((char**) KEYBLOB_SEEDS, 0x00);
	
	fflush(keyfile);
	fclose(keyfile);
}

void derive_part1(application_ctx* appstate)
{
	debug_log("Getting keys from TZ code...\n");
	FILE* TZ_f = fopen(secmon_path, FMODE_READ);
	
	fseek(TZ_f, 0, SEEK_END);
	int TZ_SIZE = ftell(TZ_f);
	fseek(TZ_f, 0, SEEK_SET);
	
	char* TZ_DATA = malloc(TZ_SIZE);
	fread(TZ_DATA, TZ_SIZE, 1, TZ_f);
	fclose(TZ_f);
	
	debug_log("Adding %s to the key file\n", "package2_key_source");
	find_and_add_key(TZ_DATA, 0x05, TZ_SIZE);
	debug_log("Adding %s to the key file\n", "aes_kek_generation_source");
	find_and_add_key(TZ_DATA, 0x06, TZ_SIZE);
	debug_log("Adding %s to the key file\n", "titlekek_source");
	find_and_add_key(TZ_DATA, 0x08, TZ_SIZE);
	
	free(TZ_DATA);
	
	hactool_init(appstate);
	pki_derive_keys(&appstate->tool_ctx.settings.keyset);
	
	debug_log("package2_key_source = ");
	for (unsigned int j = 0; j < 0x10; j++)
	{
		debug_log("%02x", appstate->tool_ctx.settings.keyset.package2_key_source[j]);
	}
	debug_log("\n");
	
	update_keyfile(1, &appstate->tool_ctx.settings.keyset);
	
	debug_log("package2_key_00 = ");
	for (unsigned int j = 0; j < 0x10; j++)
	{
		debug_log("%02x", appstate->tool_ctx.settings.keyset.package2_keys[0][j]);
	}
	debug_log("\n");
}

void final_derivation(application_ctx* appstate)
{
	debug_log("Doing final derivation...\n");
	hactool_init(appstate);
	pki_derive_keys(&appstate->tool_ctx.settings.keyset);
	debug_log("Final keys derived, adding them to the keyfile...\n");
	update_keyfile(2, &appstate->tool_ctx.settings.keyset);
	
	debug_log("Copying keyfile to real location...\n");
	char* keydata;
	
	FILE* keyfile = fopen(keyfile_path, FMODE_READ);
	fseek(keyfile, 0, SEEK_END);
	int keyfilesize = ftell(keyfile);
	fseek(keyfile, 0, SEEK_SET);
	keydata = malloc(keyfilesize);
	fread(keydata, keyfilesize, 1, keyfile);
	fclose(keyfile);
	
	FILE* newkeyfile = fopen(final_keyfile_path, FMODE_WRITE);
	fwrite(keydata, keyfilesize, 1, newkeyfile);
	fclose(newkeyfile);
	free(keydata);
	
	debug_log("Keyfile copied, that's a wrap!\n");
}