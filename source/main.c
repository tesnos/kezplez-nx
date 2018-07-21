//library includes
#include <string.h>
#include <stdio.h>
#include <switch.h>
#include <stdbool.h>
// #include <sys/stat.h>

//hactool includes
// #include "hactool/extkeys.h"
// #include "hactool/kip.h"
// #include "hactool/nca.h"
// #include "hactool/packages.h"
// #include "hactool/pki.h"
// #include "hactool/types.h"
// #include "hactool/utils.h"

//local includes
#include "graphics/gui.h"

#include "util.h"
#include "derivation.h"
#include "keys.h"
#include "kip.h"
#include "packages.h"
//#include "upload.h"


application_ctx appstate;
Thread* step_thread;


int main(int argc, char** argv)
{
	memset(&appstate, 0x00, sizeof(appstate));
	
	//app init
	mkdir("/switch/kezplez-nx\0", 777);
	gui_init();
	
	//curl init
	//upload_init();
	
	//internal variable inits
	appstate.state_id = 0;
	appstate.progress = 0;
	
	//hactool init
	get_tsec_sbk();
	hactool_init(&appstate);
	
	
	while (appletMainLoop())
	{
		hidScanInput();
		u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);
		if (kDown & KEY_PLUS) break;
		
		//Beginning
		if (appstate.state_id == 0)
		{
			if (kDown & KEY_A)
			{
				appstate.state_id = 1;
				appstate.step_completed = true;
			}
		}
		
		//After every step, try the next
		if (appstate.state_id == 1 && appstate.step_completed)
		{
			if (appstate.progress > 0)
			{
				threadClose(step_thread);
				free(step_thread);
			}
			
			//check if previous step failed
			if (R_FAILED(appstate.step_result))
			{
				appstate.state_id = 3;
				appstate.progress = appstate.step_result;
			}
			else
			{
				appstate.progress++;
			}
		}
		
		
		if (appstate.state_id == 1 && appstate.step_completed)
		{
			if (appstate.progress == 1)
			{
				step_thread = util_thread_func(dump_boot0, &appstate);
			}
			
			if (appstate.progress == 2)
			{
				step_thread = util_thread_func(dump_bcpkg_21, &appstate);
			}
			
			if (appstate.progress == 3)
			{
				step_thread = util_thread_func(extract_package2, &appstate);
			}
			
			if (appstate.progress == 4)
			{
				step_thread = util_thread_func(extract_package1_encrypted, &appstate);
			}
			
			if (appstate.progress == 5)
			{
				step_thread = util_thread_func(derive_part0, &appstate);
			}
			
			if (appstate.progress == 6)
			{
				step_thread = util_thread_func(add_other_keyblob_seeds, &appstate);
			}
			
			if (appstate.progress == 7)
			{
				step_thread = util_thread_func(extract_package1_encrypted_butagain, &appstate);
			}
			
			if (appstate.progress == 8)
			{
				step_thread = util_thread_func(decrypt_package1, &appstate);
			}
			
			if (appstate.progress == 9)
			{
				step_thread = util_thread_func(derive_part1, &appstate);
			}
			
			if (appstate.progress == 10)
			{
				step_thread = util_thread_func(extract_package2_contents, &appstate);
			}
			
			if (appstate.progress == 11)
			{
				step_thread = util_thread_func(extract_kip1s, &appstate);
			}
			
			if (appstate.progress == 12)
			{
				step_thread = util_thread_func(derive_part2_spl, &appstate);
			}
			
			if (appstate.progress == 13)
			{
				step_thread = util_thread_func(derive_part2_FS, &appstate);
			}
			
			if (appstate.progress == 14)
			{
				step_thread = util_thread_func(final_derivation, &appstate);
			}
			
			if (appstate.progress == 15)
			{
				//upload_keyfile(&appstate);
				appstate.state_id = 2;
			}
		}
		
		
		gui_beginframe();
		gui_drawframe(&appstate);
		gui_endframe();
	}
	
	
	//cleanup
	//upload_exit();
	gui_exit();
	return 0;
}