#include "sysmodules.h"

void get_eticket_rsa_kek(application_ctx* appstate)
{
    u64 tid = ETICKET_TID;
    u64 pid;
    Result rc;
    Handle debughandle = 0;

    pmdmntInitialize();
    if (R_FAILED(rc = pmdmntGetTitlePid(&pid, tid))) { debug_log("Failed to get es pid!\n"); return; }
    debug_log("Got es pid %"PRIx64".\n", pid);
    
    if (R_FAILED(rc = svcDebugActiveProcess(&debughandle, pid))) { debug_log("Failed to debug active process!\n"); return; }
    debug_log("Debug handle attached.\n");
    
    MemoryInfo meminfo;
    memset(&meminfo, 0, sizeof(MemoryInfo));
    u32 pageinfo;
    u64 addr = 0;
    
    char eticket_rsa_kek_source[KEY_SIZES[0x13] + 1], eticket_rsa_kekek_source[KEY_SIZES[0x14] + 1];
    memcpy(eticket_rsa_kek_source, nokey, 6);
    memcpy(eticket_rsa_kekek_source, nokey, 6);
    bool kek_found = false, kekek_found = false;
    
    debug_log("Searching es memory for keys...\n");
    do
    {
        svcQueryDebugProcessMemory(&meminfo, &pageinfo, debughandle, addr);
        if (meminfo.perm & Perm_R) {
            void *ES_MEM = malloc(meminfo.size);
            if(R_FAILED(svcReadDebugProcessMemory(ES_MEM, debughandle, meminfo.addr, meminfo.size))) {
                free(ES_MEM);
                debug_log("Unable to read memory. Aborting.\n");
                return;
            }
            kek_found = find_via_hash(ES_MEM, KEY_HASHES[0x13], KEY_SIZES[0x13], meminfo.size, eticket_rsa_kek_source, false);
            kekek_found = find_via_hash(ES_MEM, KEY_HASHES[0x14], KEY_SIZES[0x14], meminfo.size, eticket_rsa_kekek_source, false);
            free(ES_MEM);
        }
        addr = meminfo.addr + meminfo.size;
    } while ((addr != 0) && !kek_found && !kekek_found);

    svcCloseHandle(debughandle);
    pmdmntExit();
    printf("Read successful! Detached debug handle, exited debug monitor.\n");
    
    if ((strcmp(eticket_rsa_kek_source, nokey) == 0) || (strcmp(eticket_rsa_kek_source, nokey) == 0)) {
        debug_log("Failed to find both needed keys in es process. Aborting.\n");
        return;
    }
    char hexkey[KEY_SIZES[0x13] * 2 + 1];
    hex_of_key(eticket_rsa_kek_source, KEY_SIZES[0x13], hexkey);
    debug_log("eticket_rsa_kek_source: %s\n", hexkey);
    hex_of_key(eticket_rsa_kekek_source, KEY_SIZES[0x14], hexkey);
    debug_log("eticket_rsa_kekek_source: %s\n", hexkey);
    char rsa_oaep_kek_generation_source[sizeof(rsa_kek_mask_0)];
    for (int i = 0; i < sizeof(rsa_kek_mask_0); i++)
	{
		rsa_oaep_kek_generation_source[i] = (rsa_kek_mask_0[i] ^ rsa_kek_seed_3[i]);
	}
    hex_of_key(rsa_oaep_kek_generation_source, sizeof(rsa_oaep_kek_generation_source), hexkey);
    debug_log("rsa_oaep_kek_generation_source: %s\n", hexkey);
	
    char eticket_rsa_kek[KEY_SIZES[0x15]];
    generate_kek( (u8*) eticket_rsa_kek,
                  (u8*) eticket_rsa_kekek_source,
                  appstate->tool_ctx.settings.keyset.master_keys[0],
                  (u8*) rsa_oaep_kek_generation_source,
                  (u8*) eticket_rsa_kek_source );
    
    char eticket_rsa_kek_hex[KEY_SIZES[0x15] * 2];
    find_via_hash(eticket_rsa_kek, KEY_HASHES[0x15], KEY_SIZES[0x15], KEY_SIZES[0x15], eticket_rsa_kek_hex, true);
    debug_log("%s: %s\n", KEY_NAMES[0x15], eticket_rsa_kek_hex);
    debug_log("Adding %s to the key file\n", KEY_NAMES[0x15]);
    add_to_key_file(KEY_NAMES[0x15], eticket_rsa_kek_hex);
    
    debug_log("Finished deriving eticket_rsa_kek!\n");
}
