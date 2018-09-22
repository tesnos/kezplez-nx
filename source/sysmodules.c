#include "sysmodules.h"

void dump_and_decrypt_es(application_ctx* appstate)
{
    DIR* dir;
    struct dirent* ent;
	FsFileSystem fs;
    const char* buff = "";
    const char registered_path[256] = "SYSTEM:/Contents/registered\0";
    char tmppath[256];
    char es_path[256] = "/switch/kezplez-nx/es\0";
    
    mkdir(es_path, 777);

    debug_log("Preparing nca context...\n");
    nca_ctx_t nca_ctx;
    nca_init(&appstate->nca_ctx);
    nca_ctx.tool_ctx = &appstate->tool_ctx;
    nca_ctx.tool_ctx->file_type = FILETYPE_NCA;
    nca_ctx.tool_ctx->settings.exefs_dir_path.enabled = 1;
	filepath_set(&nca_ctx.tool_ctx->settings.exefs_dir_path.path, es_path);
	
    debug_log_toscreen(appstate, "Locating ES nca...\n");

    debug_log("Opening SYSTEM as bis filesystem\n");
	Result rc = fsOpenBisFileSystem(&fs, 31, buff);
    if (R_FAILED(rc)) { debug_log("Failed to open bis filesystem!\n"); return; }
    debug_log("Mounting SYSTEM\n");
	int rc0 = fsdevMountDevice("SYSTEM", fs);
    if (rc0 == -1) { debug_log("Failed to mount SYSTEM!\n"); fsFsClose(&fs); return; }

    dir = opendir(registered_path);
    
    while ((ent = readdir(dir)))
    {
        if (ent->d_name[0] == '.')
		{
			continue;
		}

        strcpy(tmppath, registered_path);
		strcat(tmppath, "/");
		strcat(tmppath, ent->d_name);

        debug_log("Checking nca header of %s\n", ent->d_name);
        nca_ctx.file = fopen(tmppath, FMODE_READ);
        nca_decrypt_header(&nca_ctx);
        if (nca_ctx.header.title_id == 0x0100000000000033 && nca_ctx.header.content_type == 0)
        {
            debug_log_toscreen(appstate, "Found es nca. Decrypting es...\n");
            nca_process(&nca_ctx);
            debug_log_toscreen(appstate, "es decrypted!\n");
            nca_free_section_contexts(&nca_ctx);
            fclose(nca_ctx.file);
            break;
        }
        fclose(nca_ctx.file);
    }
    closedir(dir);
    
    fsdevUnmountDevice("SYSTEM");
	fsFsClose(&fs);

    strcat(es_path, "/main");

    debug_log_toscreen(appstate, "Getting keys from es code...\n");
    FILE* ES_f = safe_fopen(es_path, FMODE_READ);

    fseek(ES_f, 0, SEEK_END);
	int ES_SIZE = ftell(ES_f);
	fseek(ES_f, 0, SEEK_SET);
	
	char* ES_DATA = malloc(ES_SIZE);
	fread(ES_DATA, ES_SIZE, 1, ES_f);
	fclose(ES_f);

    // rewrite of find_via_hash to accomodate need for raw output instead of hex string
    unsigned char rawkey[KEY_SIZES[0x13]];
	unsigned char digest[KEY_SIZES[0x13] * 2];
	char eticket_rsa_kek_source[KEY_SIZES[0x13]];
	for (int i = 0; i < (ES_SIZE - KEY_SIZES[0x13]); i++)
	{
		memcpy(rawkey, ES_DATA + i, KEY_SIZES[0x13]);
		mbedtls_sha256_ret(rawkey, KEY_SIZES[0x13], digest, 0);
		if (memcmp((char*) digest, KEY_HASHES[0x13], sizeof(digest)) == 0)
		{
			memcpy(eticket_rsa_kek_source, rawkey, KEY_SIZES[0x13]);
			break;
		}
	}
	
    debug_log("eticket_rsa_kek_source: ");
	for (int i = 0; i < sizeof(eticket_rsa_kek_source); i++)
	{
		debug_log("%02x", eticket_rsa_kek_source[i]);
	}
    debug_log("\n");

    memset(rawkey, 0x00, KEY_SIZES[0x14]);
	memset(digest, 0x00, KEY_SIZES[0x14] * 2);
	char eticket_rsa_kekek_source[KEY_SIZES[0x14]];
	for (int i = 0; i < (ES_SIZE - KEY_SIZES[0x14]); i++)
	{
		memcpy(rawkey, ES_DATA + i, KEY_SIZES[0x14]);
		mbedtls_sha256_ret(rawkey, KEY_SIZES[0x14], digest, 0);
		if (memcmp((char*) digest, KEY_HASHES[0x14], sizeof(digest)) == 0)
		{
			memcpy(eticket_rsa_kekek_source, rawkey, KEY_SIZES[0x14]);
			break;
		}
	}

    debug_log("eticket_rsa_kekek_source: ");
	for (int i = 0; i < sizeof(eticket_rsa_kekek_source); i++)
	{
		debug_log("%02x", eticket_rsa_kekek_source[i]);
	}
    debug_log("\n");

    debug_log("rsa_oaep_kek_generation_source: ");
    char rsa_oaep_kek_generation_source[0x10];
    for (int i = 0; i < sizeof(rsa_oaep_kek_generation_source); i++)
	{
		rsa_oaep_kek_generation_source[i] = (rsa_kek_mask_0[i] ^ rsa_kek_seed_3[i]);
        debug_log("%02x", rsa_oaep_kek_generation_source[i]);
	}
    debug_log("\n");

    char kek_unwrapped[0x10], kekek_unwrapped[0x10], eticket_rsa_kek[KEY_SIZES[0x15]];
    aes_ctx_t *aes_ctx;
    aes_ctx = new_aes_ctx(&appstate->tool_ctx.settings.keyset.master_keys[0], 0x10, AES_MODE_ECB);
	aes_decrypt(aes_ctx, kek_unwrapped, rsa_oaep_kek_generation_source, 0x10);
	free_aes_ctx(aes_ctx);
    aes_ctx = new_aes_ctx(kek_unwrapped, 0x10, AES_MODE_ECB);
	aes_decrypt(aes_ctx, kekek_unwrapped, eticket_rsa_kekek_source, 0x10);
	free_aes_ctx(aes_ctx);
	aes_ctx = new_aes_ctx(kekek_unwrapped, 0x10, AES_MODE_ECB);
	aes_decrypt(aes_ctx, eticket_rsa_kek, eticket_rsa_kek_source, 0x10);
	free_aes_ctx(aes_ctx);
    debug_log("kek_unwrapped: ");
    for (int i = 0; i < 0x10; i++)
	{
		debug_log("%02x", kek_unwrapped[i]);
	}
	debug_log("\n");

    debug_log("kekek_unwrapped: ");
    for (int i = 0; i < 0x10; i++)
	{
		debug_log("%02x", kekek_unwrapped[i]);
	}
	debug_log("\n");

    char eticket_rsa_kek_hex[KEY_SIZES[0x15] * 2];
    hex_of_key(eticket_rsa_kek, KEY_SIZES[0x15], eticket_rsa_kek_hex);
    debug_log("%s: %s\n", KEY_NAMES[0x15], eticket_rsa_kek_hex);
    debug_log("Adding %s to the key file\n", KEY_NAMES[0x15]);
    add_to_key_file(KEY_NAMES[0x15], eticket_rsa_kek_hex);
    
    debug_log("Finished deriving eticket_rsa_kek!\n");
}
