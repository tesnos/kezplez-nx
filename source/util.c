#include "util.h"


#ifdef LOGGING_ENABLED
const char log_path[256] = "/switch/kezplez-nx/log.txt\0";
#endif

const char keyfile_path[256] = "/switch/kezplez-nx/keys.txt\0";
const char hekate_fusedump_path[256] = "/Backup/Dumps/fuses.bin\0";
const char hekate_tsecdump_path[256] = "/Backup/Dumps/tsec_key.bin\0";


Thread* util_thread_func(void (*func)(application_ctx*), application_ctx* appstate)
{
	Thread* func_thread = malloc(sizeof(Thread));
	
	appstate->thread_started = false;
	
	char* thread_args = malloc(sizeof(func) + sizeof(appstate));
	memcpy(thread_args, &func, sizeof(func));
	memcpy(thread_args + sizeof(func), &appstate, sizeof(appstate));
	
	threadCreate(func_thread, (void (*)(void *)) func, thread_args, 0x20000, 0x2C, -2);
	threadStart(func_thread);
	
	while(!appstate->thread_started) {  } //Wait until thread has started and made local argument copies to free the arguments
	free(thread_args);
	
	return func_thread;
}

void util_thread_wrapper(void (*func)(application_ctx*), application_ctx* appstate)
{
	appstate->step_completed = false;
	
	application_ctx* local_appstate = appstate;
	void (*local_func)(application_ctx*) = func;
	
	appstate->thread_started = true;
	local_func(local_appstate);
	
	appstate->step_completed = true;
}

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
	FILE* keyfile = safe_open_key_file();
	
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
	
	FILE* dbg_f = fopen(log_path, FMODE_APPEND);
	
	fwrite(log_buffer, strlen(log_buffer), 1, dbg_f);
	memcpy(appstate->log_buffer, log_buffer, 256);
	
	fflush(dbg_f);
	fclose(dbg_f);
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
	
	FILE* dbg_f = fopen(log_path, FMODE_APPEND);
	
	fwrite(log_buffer, strlen(log_buffer), 1, dbg_f);
	
	fflush(dbg_f);
	fclose(dbg_f);
#endif

}