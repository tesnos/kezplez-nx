//library includes
#include <switch.h>
#include <stdbool.h>
#include <lz4.h>

//hactool includes
#include "hactool/pki.h"
#include "hactool/types.h"
#include "hactool/nca.h"
#include "hactool/extkeys.h"

//local includes
#include "graphics/gui.h"
#include "util.h"

//internal definitions
char keyfilepath[10] = "/keys.txt\0";

int appstate, progress, step_result, fail_result;
FILE* keyfile;
bool step_completed;
Thread* step_thread;


//hactool-based definitions
hactool_ctx_t tool_ctx;
nca_ctx_t nca_ctx;


void hactool_init()
{
	memset(&tool_ctx, 0, sizeof(tool_ctx));
	tool_ctx.action = ACTION_INFO | ACTION_EXTRACT;
	//key init
	keyfile = fopen(keyfilepath, "wb");
	pki_initialize_keyset(&tool_ctx.settings.keyset, KEYSET_RETAIL);
	extkeys_initialize_keyset(&tool_ctx.settings.keyset, keyfile);
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
	dump_bis_partition("/boot0.bin", 0);
}

void dump_bcpkg_21()
{
	dump_bis_partition("/BCPKG_21_NormalMain.bin", 21);
}


int main(int argc, char** argv)
{
	//app init
	gui_init();
	
	//internal variable inits
	appstate = 0;
	progress = 0;
	fail_result = 0;
	
	//hactool init
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
				appstate = 2;
			}
		}
		
		
		gui_beginframe();
		gui_drawframe(progress);
		gui_endframe();
	}
	
	
	gui_exit();
	return 0;
}