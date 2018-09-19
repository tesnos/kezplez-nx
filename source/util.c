#include "util.h"


#ifdef LOGGING_ENABLED
const char log_path[256] = "/switch/kezplez-nx/log.txt\0";
#endif

const char keyfile_path[256] = "/switch/kezplez-nx/keys.txt\0";
const char hekate_fusedump_path[256] = "/Backup/Dumps/fuses.bin\0";
const char hekate_tsecdump_path[256] = "/Backup/Dumps/tsec_key.bin\0";


//This is disgusting, but I couldn't get thread args to work so here we are
//application_ctx* thread_appstate = NULL;
//void (*thread_func)(application_ctx*) = NULL;
bool thread_dummied = false;
FILE* dbg_f = NULL;


Thread* util_thread_func(void (*func)(application_ctx*), application_ctx* appstate)
{
	if (!thread_dummied) { thread_dummy_run(appstate); }
	
	debug_log("setting up thread-");
	Thread* func_thread = malloc(sizeof(Thread));
	
	appstate->thread_started = false;
	
	debug_log("a");
	u64* thread_args = malloc(sizeof(u64*) * 2);
	thread_args[0] = (u64) appstate;
	thread_args[1] = (u64) func;
	
	//thread_func = func;
	//thread_appstate = appstate;
	
	debug_log("b-%08x-%08x-%08x-", thread_args, thread_args[0], thread_args[1]);
	//debug_log("b");
	//Result rc = threadCreate(func_thread, util_thread_wrapper, thread_args, 0x20000, 0x2C, -2);
	Result rc = threadCreate(func_thread, (void (*)(void*)) thread_tester, thread_args, 0x2000000, 0x2C, -2);
	
	debug_log("c%08x", rc);
	rc = threadStart(func_thread);
	
	usleep(250000);
	while(!appstate->thread_started) {  } //Wait until thread has started and made local argument copies to free the arguments
	//debug_log("d%08x", rc);
	//debug_log("e");
	free(thread_args);
	
	//debug_log("f\n");
	return func_thread;
}

//don't even fuckin ask
void thread_dummy_run(application_ctx* appstate)
{
	Thread* func_thread = malloc(sizeof(Thread));
	
	//u64* thread_args = malloc(sizeof(u64*) * 1);
	//thread_args[0] = (u64) appstate;
	
	threadCreate(func_thread, (void (*)(void*)) thread_dummy, NULL, 0x2000000, 0x2C, -2);
	threadStart(func_thread);
	
	usleep(250000);
	
	threadClose(func_thread);
	free(func_thread);
	
	thread_dummied = true;
}

void thread_dummy(void* args)
{
	// u64* thread_args = (u64*) args;
	// application_ctx* appstate = (application_ctx*) thread_args[0];
	return;
}

void thread_tester(void* args)
{
	u64* thread_args = (u64*) args;
	
	application_ctx* appstate = (application_ctx*) thread_args[0];
	appstate->step_completed = false;
	appstate->thread_started = true;
	
	void (*func)(application_ctx*) = (void (*)(application_ctx*)) thread_args[1];
	
	debug_log("you dream in color-%08x-%08x-%08x\n", thread_args, appstate, func);

	func(appstate);
	
	appstate->step_completed = true;
	return;
}

// void util_thread_wrapper(void* args)
// {
	// u64* thread_args = (u64*) args;
	// void (*func)(application_ctx*) = (void (*)(application_ctx*)) thread_args[0];
	// application_ctx* appstate = (application_ctx*) thread_args[1];
	
	// thread_appstate->step_completed = false;
	// debug_log("hey now\n");
	// thread_appstate->thread_started = true;
	// thread_func(thread_appstate);
	// debug_log("hey now\n");
	
	// thread_appstate->step_completed = true;
// }

u32 read_u32_le(FILE* targetfile)
{
	u8 buf[4];
	fread(buf, 4, 1, targetfile);
	return (buf[3] << 24) + (buf[2] << 16) + (buf[1] << 8) + (buf[0]);
}

u32 read_u32_be(FILE* targetfile)
{
	u8 buf[4];
	fread(buf, 4, 1, targetfile);
	return (buf[0] << 24) + (buf[1] << 16) + (buf[2] << 8) + (buf[3]);
}

FILE* safe_open_key_file()
{
	FILE* attempted_keyfile = fopen(keyfile_path, FMODE_APPEND);
	if (attempted_keyfile == NULL)
	{
		attempted_keyfile = fopen(keyfile_path, FMODE_WRITE);
		fclose(attempted_keyfile);
		attempted_keyfile = fopen(keyfile_path, FMODE_APPEND);
	}
	
	return attempted_keyfile;
}

void hactool_init(application_ctx* appstate)
{
	memset(&appstate->tool_ctx, 0, sizeof(appstate->tool_ctx));
	appstate->tool_ctx.action = ACTION_INFO | ACTION_EXTRACT;
	// key init
	FILE* keyfile = fopen(keyfile_path, FMODE_READ);
	
	pki_initialize_keyset(&appstate->tool_ctx.settings.keyset, KEYSET_RETAIL);
	extkeys_initialize_keyset(&appstate->tool_ctx.settings.keyset, keyfile);
	
	appstate->nca_ctx.tool_ctx = &appstate->tool_ctx;
	
	pki_derive_keys(&appstate->tool_ctx.settings.keyset);
	fclose(keyfile);
}


void debug_log_toscreen(application_ctx* appstate, char* log_text, ...)
{

#ifdef LOGGING_ENABLED
	char log_buffer[256]; log_buffer[255] = 0x00;
	va_list args;
	va_start(args, log_text);
	vsnprintf(log_buffer, 255, log_text, args);
	va_end(args);
	
	if (dbg_f == NULL) { dbg_f = fopen(log_path, FMODE_APPEND); }
	if (dbg_f == NULL) { return; }
	
	fwrite(log_buffer, strlen(log_buffer), 1, dbg_f);
	memcpy(appstate->log_buffer, log_buffer, 256);
	
	fflush(dbg_f);
#endif

}

void debug_log(char* log_text, ...)
{

#ifdef LOGGING_ENABLED
	char log_buffer[256]; log_buffer[255] = 0x00;
	va_list args;
	va_start(args, log_text);
	vsnprintf(log_buffer, 255, log_text, args);
	va_end(args);

	if (dbg_f == NULL) { dbg_f = fopen(log_path, FMODE_APPEND); }
	if (dbg_f == NULL) { return; }
	
	fwrite(log_buffer, strlen(log_buffer), 1, dbg_f);
	
	fflush(dbg_f);
#endif

}