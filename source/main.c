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
#include "gui.h"

#include "util.h"
#include "derivation.h"
#include "keys.h"
#include "kips.h"
#include "packages12.h"
//#include "upload.h"


application_ctx appstate;
Thread* step_thread;


int main(int argc, char** argv)
{
	util_hold_appstate(&appstate);
	
	gui_init();
	memset(&appstate, 0x00, sizeof(appstate));
	appstate.state_id = 0;
	appstate.progress = 0;
	#ifdef LOGGING_ENABLED
	memset(appstate.log_buffer, 0x00, 256);
	#endif
	
	//clears out/creates log and keyfile
	remove(log_path);
	remove(keyfile_path);
	fclose(safe_open_key_file());
	fclose(safe_fopen(log_path, FMODE_WRITE));
	
	//app init
	debug_log("general application initialization\n");
	mkdir("/switch/kezplez-nx\0", 777);
	mkdir(package1_dir_path, 777);
	mkdir(package2_dir_path, 777);
	
	//curl init
	//upload_init();
	
	//dump locating
	debug_log("locating dumps...\n");
	get_hekate_dump_prefix();
	prepend_hdp((char*) hekate_fusedump_path, hekate_fusedump_path_full);
	prepend_hdp((char*) hekate_tsecdump_old_path, hekate_tsecdump_old_path_full);
	prepend_hdp((char*) hekate_tsecdump_new_path, hekate_tsecdump_new_path_full);
	prepend_hdp((char*) hekate_boot0_path, hekate_boot0_path_full);
	prepend_hdp((char*) hekate_package2_decrypted_path, hekate_package2_decrypted_path_full);
	prepend_hdp((char*) hekate_package2_ini1_path, hekate_package2_ini1_path_full);
	prepend_hdp((char*) hekate_package2_kernel_path, hekate_package2_kernel_path_full);
	
	//hactool init
	debug_log("loading in tsec and sbk\n");
	get_tsec_sbk();
	// if (appstate == -1) { goto exit; }
	debug_log("preparing hactool\n");
	hactool_init(&appstate);
	// if (appstate == -1) { goto exit; }
	
	
	debug_log("main loop begins\n");
	while (appletMainLoop())
	{
		hidScanInput();
		u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);
		if (kDown & KEY_PLUS) { break; }
		
		//Beginning
		if (appstate.state_id == 0)
		{
			if (kDown & KEY_A)
			{
				appstate.state_id = 1;
				appstate.step_completed = true;
				appstate.progress = 0;
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
				step_thread = util_thread_func(extract_package2_simple, &appstate);
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
	
	
// exit:;
	//cleanup
	gui_exit();
	return 0;
}