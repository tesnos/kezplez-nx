#include "packages12.h"


const char boot0_path[256] = "/switch/kezplez-nx/boot0.bin\0";
const char package1_dir_path[256] = "/switch/kezplez-nx/package1\0";
const char package1_path[256] = "/switch/kezplez-nx/package1.bin\0";
const char hekate_boot0_path[256] = "/Backup/BOOT0\0";
const char bcpkg_21_path[256] = "/switch/kezplez-nx/BCPKG_21_NormalMain.bin\0";
const char package2_dir_path[256] = "/switch/kezplez-nx/package2\0";
const char package2_path[256] = "/switch/kezplez-nx/package2.bin\0";
const char hekate_package2_decrypted_path[256] = "/Backup/pkg2/pkg2_decr.bin\0";
const char package2_decrypted_path[256] = "/switch/kezplez-nx/package2/Decrypted.bin\0";
const char hekate_package2_ini1_path[256] = "/Backup/pkg2/ini1.bin\0";
const char package2_ini1_path[256] = "/switch/kezplez-nx/package2/INI1.bin\0";
const char package2_ini1_dir_path[256] = "/switch/kezplez-nx/ini1\0";

const char hekate_package2_kernel_path[256] = "/Backup/pkg2/kernel.bin\0";
const char package2_kernel_path[256] = "/switch/kezplez-nx/package2/Kernel.bin\0";

char BOOT0_DATA[BOOT0_SIZE];


void dump_bis_partition(const char* filepath, u32 partition_id)
{
	FILE* dumpfile = fopen(filepath, FMODE_WRITE);
	FsStorage partition;
	u64 partition_size, dump_progress, bytes_to_dump;
	
	debug_log("Opening bis storage partition of id %08x\n", partition_id);
	Result rc = fsOpenBisStorage(&partition, partition_id);
	if (R_FAILED(rc)) { debug_log("Failed to open partition of id %08x!\n", partition_id); return; }
	
	rc = fsStorageGetSize(&partition, &partition_size);
	if (R_FAILED(rc)) { debug_log("Failed to get size of partition of id %08x!\n", partition_id);return; }
	debug_log("Partition is %08x bytes large\n", partition_size);
	
	size_t dump_buffer_size = 0x10000;
	u8 dump_buffer[dump_buffer_size];
	
	dump_progress = 0;
	debug_log("Dumping partition (bytes dumped so far: %08x)\n", dump_progress);
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
		if (R_FAILED(rc)) { debug_log("Failed to read from partition of id %08x!\n", partition_id); return; }
		
		fwrite(dump_buffer, bytes_to_dump, 1, dumpfile);
		
		dump_progress += bytes_to_dump;
		debug_log("Dumping partition (bytes dumped so far: %08x)\n", dump_progress);
	}
	
	debug_log("Dump complete, closing partition\n");
	fsStorageClose(&partition);
	fclose(dumpfile);
}

void dump_boot0(application_ctx* appstate)
{
	FILE* hekate_boot0_f = fopen(hekate_boot0_path, FMODE_READ);
	if (hekate_boot0_f != NULL) { appstate->boot0_is_from_hekate = true; }
	else { appstate->boot0_is_from_hekate = false; }
	
	if (appstate->boot0_is_from_hekate)
	{
		debug_log("BOOT0 was dumped via hekate so copying it from there\n");
		FILE* real_boot0_f = fopen(boot0_path, FMODE_WRITE);
		
		fseek(hekate_boot0_f, 0, SEEK_END);
		int boot0_temp_size = ftell(hekate_boot0_f);
		fseek(hekate_boot0_f, 0, SEEK_SET);
		
		char* boot0_temp_buf = malloc(boot0_temp_size);
		fread(boot0_temp_buf, boot0_temp_size, 1, hekate_boot0_f);
		fwrite(boot0_temp_buf, boot0_temp_size, 1, real_boot0_f);
		
		fclose(real_boot0_f);
		fclose(hekate_boot0_f);
		free(boot0_temp_buf);
	}
	else
	{
		debug_log("Dumping BOOT0 via fs because it was not dumped from hekate\n");
		dump_bis_partition(boot0_path, 0);
	}
	
	debug_log("BOOT0 Dumped.\n");
}

void dump_bcpkg_21(application_ctx* appstate)
{
	FILE* hekate_pkg2_f = fopen(hekate_package2_decrypted_path, FMODE_READ);
	FILE* hekate_ini1_f = fopen(hekate_package2_ini1_path, FMODE_READ);
	FILE* hekate_kern_f = fopen(hekate_package2_kernel_path, FMODE_READ);
	
	if (hekate_pkg2_f != NULL && hekate_ini1_f != NULL && hekate_kern_f != NULL)
	{
		appstate->pkg2_is_from_hekate = true;
	}
	else
	{
		appstate->pkg2_is_from_hekate = false;
		
		if (hekate_pkg2_f != NULL) { fclose(hekate_pkg2_f); }
		if (hekate_ini1_f != NULL) { fclose(hekate_ini1_f); }
		if (hekate_kern_f != NULL) { fclose(hekate_kern_f); }
	}
	
	
	if (appstate->pkg2_is_from_hekate)
	{
		debug_log("package2 was dumped via hekate so copying it from there\n");
		mkdir(package2_dir_path, 777);
		
		for (int i = 0; i < 3; i++)
		{
			FILE* target_f;
			FILE* source_f;
			
			if (i == 0) { source_f = hekate_pkg2_f; }
			if (i == 1) { source_f = hekate_ini1_f; }
			if (i == 2) { source_f = hekate_kern_f; }
			
			if (i == 0) { target_f = fopen(package2_decrypted_path, FMODE_WRITE); }
			if (i == 1) { target_f = fopen(package2_ini1_path, FMODE_WRITE); }
			if (i == 2) { target_f = fopen(package2_kernel_path, FMODE_WRITE); }
			
			
			fseek(source_f, 0, SEEK_END);
			int temp_size = ftell(source_f);
			fseek(source_f, 0, SEEK_SET);
			
			char* temp_buf = malloc(temp_size);
			fread(temp_buf, temp_size, 1, source_f);
			fwrite(temp_buf, temp_size, 1, target_f);
			
			fclose(target_f);
			fclose(source_f);
			free(temp_buf);
		}
	}
	else
	{
		debug_log("Dumping package2 via fs because it was not dumped from hekate\n");
		dump_bis_partition(bcpkg_21_path, 21);
	}
	
	debug_log("package2 Dumped.\n");
}

// void extract_package2_simple(application_ctx* appstate)
// {
	// FILE* hekate_boot0_f = fopen(hekate_boot0_path, FMODE_READ);
	// if (hekate_boot0_f != NULL) { appstate->boot0_is_from_hekate = true; }
	// else { appstate->boot0_is_from_hekate = false; }
	
	// if (appstate->boot0_is_from_hekate)
	// {
		// debug_log("BOOT0 was duped via hekate so copying it from there\n");
		// FILE* real_boot0_f = fopen(boot0_path, FMODE_WRITE);
		
		// fseek(hekate_boot0_f, 0, SEEK_END);
		// int boot0_temp_size = ftell(hekate_boot0_f);
		// fseek(hekate_boot0_f, 0, SEEK_SET);
		
		// char* boot0_temp_buf = malloc(boot0_temp_size);
		// fread(boot0_temp_buf, boot0_temp_size, 1, hekate_boot0_f);
		// fwrite(boot0_temp_buf, boot0_temp_size, 1, real_boot0_f);
		
		// fclose(real_boot0_f);
		// fclose(hekate_boot0_f);
		// free(boot0_temp_buf);
	// }
	// else
	// {
		// debug_log("Dumping BOOT0 via fs because it was not dumped from hekate\n");
		// dump_bis_partition(boot0_path, 0);
	// }
	
	// debug_log("BOOT0 Dumped.\n");
// }

void extract_package2_simple(application_ctx* appstate)
{
	debug_log("Hello from extract_package2_simple!\n");
	
	
	if (appstate->pkg2_is_from_hekate)
	{
		debug_log("No need to extract package2 from BCPKG_21 because it was dumped from hekate\n");
	}
	else
	{
		debug_log("Extracting package2 from BCPKG_21 because it was not dumped from hekate\n");
		FILE* BCPKG_21_f = fopen(bcpkg_21_path, FMODE_READ);
		FILE* PKG21_f = fopen(package2_path, FMODE_WRITE);
		
		char PKG21_DATA[PKG21_SIZE];
		char BCPKG_21_DATA[BCPKG_21_SIZE];
		
		fread(BCPKG_21_DATA, BCPKG_21_SIZE, 1, BCPKG_21_f);
		memcpy(PKG21_DATA, BCPKG_21_DATA + PKG21_BEGIN, PKG21_SIZE);
		fwrite(PKG21_DATA, PKG21_SIZE, 1, PKG21_f);
		
		fclose(PKG21_f);
		fclose(BCPKG_21_f);
		debug_log("Extraction complete.\n");
	}
}

void extract_package1_encrypted(application_ctx* appstate)
{
	debug_log("Extracting package1 from BOOT0, the wrong way\n");
	FILE* BOOT0_f = fopen(boot0_path, FMODE_READ);
	FILE* PKG11_f = fopen(package1_path, FMODE_WRITE);
	
	char PKG11_DATA[PKG11_SIZE];
	char BOOT0_DATA[BOOT0_SIZE];
	char* PKG11_LOC = NULL;
	
	fread(BOOT0_DATA, BOOT0_SIZE, 1, BOOT0_f);
	
	char* PKG11_SEARCH_BEGIN = BOOT0_DATA + 0x100000;
	char* PKG11_SEARCH_END = BOOT0_DATA + 0x140000;
	char* PKG11_SEARCH_POS = PKG11_SEARCH_BEGIN;
	u32 PKG11_TARGET_STR_BE = 0x504B3131;
	u32 PKG11_TARGET_STR_LE = 0x31314B50;
	
	debug_log("Searching for target string PK11...");
	
	for (; PKG11_SEARCH_POS < PKG11_SEARCH_END; PKG11_SEARCH_POS += 4)
	{
		u32 PKG11_TARGET_TEST = *((u32*) PKG11_SEARCH_POS);
		if (PKG11_TARGET_TEST == PKG11_TARGET_STR_BE || PKG11_TARGET_TEST == PKG11_TARGET_STR_LE)
		{
			PKG11_LOC = PKG11_SEARCH_POS;
			debug_log("Found!\n");
			break;
		}
	}
	if (PKG11_SEARCH_POS >= PKG11_SEARCH_END) { debug_log("Not Found! Is BOOT0 corrupt?\n"); }
	
	memcpy(PKG11_DATA, PKG11_LOC, PKG11_SIZE);
	fwrite(PKG11_DATA, PKG11_SIZE, 1, PKG11_f);
	
	fclose(PKG11_f);
	fclose(BOOT0_f);
	
	debug_log("Extraction complete.\n");
}

void extract_package1_encrypted_butagain(application_ctx* appstate)
{
	debug_log("Extracting package1 from BOOT0, the right way\n");
	
	FILE* BOOT0_f = fopen(boot0_path, FMODE_READ);
	FILE* PKG11_f = fopen(package1_path, FMODE_WRITE);
	
	char PKG11_DATA[PKG11_SIZE];
	
	fread(BOOT0_DATA, BOOT0_SIZE, 1, BOOT0_f);
	memcpy(PKG11_DATA, BOOT0_DATA + PKG11_REALBEGIN, PKG11_SIZE);
	fwrite(PKG11_DATA, PKG11_SIZE, 1, PKG11_f);
	
	fclose(PKG11_f);
	fclose(BOOT0_f);
	
	debug_log("Extraction complete.\n");
}

void decrypt_package1(application_ctx* appstate)
{
	debug_log("Decrypting package1...\n");
	hactool_init(appstate);
	hactool_ctx_t* tool_ctx = &appstate->tool_ctx;
	
	debug_log("Retrieving keyblobs from boot0...\n");
	nca_keyset_t new_keyset;
	memcpy(&new_keyset, &tool_ctx->settings.keyset, sizeof(new_keyset));
	
	// for (unsigned int i = 0; i < 0x10; i++) {
		// if (tool_ctx->settings.keygen_sbk[i] != 0) {
			// memcpy(new_keyset.secure_boot_key, tool_ctx->settings.keygen_sbk, 0x10);
		// }
	// }
	// for (unsigned int i = 0; i < 0x10; i++) {
		// if (tool_ctx->settings.keygen_tsec[i] != 0) {
			// memcpy(new_keyset.tsec_key, tool_ctx->settings.keygen_tsec, 0x10);
		// }
	// }
	
	for (unsigned int i = 0; i < 0x20; i++) {
		// debug_log("keyblob_key_source_%02x = ", i);
		// for (unsigned int j = 0; j < 0x10; j++)
		// {
			// debug_log("%02x", &appstate->tool_ctx.settings.keyset.keyblob_key_sources[i][j]);
		// }
		// debug_log("\n");
		
		// debug_log("copied_keyblob_key_source_%02x = ", i);
		// for (unsigned int j = 0; j < 0x10; j++)
		// {
			// debug_log("%02x", new_keyset.keyblob_key_sources[i][j]);
		// }
		// debug_log("\n");
		
		// debug_log("encrypted_keyblob_%02x = ", i);
		// for (unsigned int j = 0; j < 0xB0; j++)
		// {
			// debug_log("%02x", BOOT0_DATA[0x180000 + (0x200 * i) + j]);
		// }
		// debug_log("\n");
		
		memcpy(new_keyset.encrypted_keyblobs[i], BOOT0_DATA + 0x180000 + (0x200 * i), 0xB0);
		
		// debug_log("copied_encrypted_keyblob_%02x = ", i);
		// for (unsigned int j = 0; j < 0xB0; j++)
		// {
			// debug_log("%02x", new_keyset.encrypted_keyblobs[i][j]);
		// }
		// debug_log("\n");
	}
	
	debug_log("Keyblobs obtained, deriving all possible keys...\n");
	pki_derive_keys(&new_keyset);
	debug_log("Saving newly obtained keys...\n");
	update_keyfile(0, &new_keyset);
	
	
	//actual package1 decryption
	debug_log("Preparing for package1 decryption...\n");
	hactool_init(appstate);
	tool_ctx->file = fopen(package1_path, FMODE_READ);
	tool_ctx->file_type = FILETYPE_PACKAGE1;
	filepath_set(&tool_ctx->settings.pk11_dir_path, package1_dir_path);
	
	pk11_ctx_t pk11_ctx;
	memset(&pk11_ctx, 0, sizeof(pk11_ctx));
	pk11_ctx.file = tool_ctx->file;
	pk11_ctx.tool_ctx = tool_ctx;
	debug_log("Decrypting package1...\n");
	pk11_process(&pk11_ctx);
	
	if (pk11_ctx.pk11) {
		free(pk11_ctx.pk11);
	}
	
	fclose(tool_ctx->file);
	debug_log("Package1 Decrypted!\n");
}

void extract_package2_contents(application_ctx* appstate)
{
	debug_log("Extracting package2...\n");
	hactool_ctx_t tool_ctx = *(&appstate->tool_ctx);
	
	// hactool_init(appstate);
	// pki_derive_keys(&tool_ctx.settings.keyset);
	// update_keyfile(1, &tool_ctx.settings.keyset);
	
	hactool_init(appstate);
	
	if (appstate->pkg2_is_from_hekate)
	{
		debug_log("Package2 was from hekate, so doing ini1 extraction instead\n");
		tool_ctx.file = fopen(package2_ini1_path, FMODE_READ);
		tool_ctx.file_type = FILETYPE_INI1;
		filepath_set(&tool_ctx.settings.ini1_dir_path, package2_ini1_dir_path);
		
		ini1_ctx_t ini1_ctx;
		memset(&ini1_ctx, 0, sizeof(ini1_ctx));
		ini1_ctx.file = tool_ctx.file;
		ini1_ctx.tool_ctx = &tool_ctx;
		debug_log("Extracting INI1...");
		ini1_process(&ini1_ctx);
		if (ini1_ctx.header) {
			free(ini1_ctx.header);
		}
	}
	else
	{
		debug_log("Package2 was not from hekate, so doing full extraction\n");
		tool_ctx.file = fopen(package2_path, FMODE_READ);
		tool_ctx.file_type = FILETYPE_PACKAGE2;
		filepath_set(&tool_ctx.settings.pk21_dir_path, package2_dir_path);
		filepath_set(&tool_ctx.settings.ini1_dir_path, package2_ini1_dir_path);
		
		pk21_ctx_t pk21_ctx;
		memset(&pk21_ctx, 0, sizeof(pk21_ctx));
		pk21_ctx.file = tool_ctx.file;
		pk21_ctx.tool_ctx = &tool_ctx;
		debug_log("Extracting package2...");
		pk21_process(&pk21_ctx);
		if (pk21_ctx.sections) {
			free(pk21_ctx.sections);
		}
	}
	
	fclose(tool_ctx.file);
	debug_log("Extraction Complete!");
}