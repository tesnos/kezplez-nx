#ifndef UTIL_H
#define UTIL_H

#include <dirent.h>
#include <switch.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>

#include "extkeys.h"
#include "nca.h"
#include "pki.h"
#include "types.h"


#define FMODE_READ   "rb"
#define FMODE_WRITE  "wb"
#define FMODE_EDIT   "rb+"
#define FMODE_APPEND "ab+"

#define PKG11_SIZE 0x40000
#define PROGRESS_TOTAL 15


#define LOGGING_ENABLED
#ifdef LOGGING_ENABLED
extern const char log_path[256];
#endif

extern const char keyfile_path[256];
extern const char hekate_fusedump_path[256];
extern const char hekate_tsecdump_old_path[256];
extern const char hekate_tsecdump_new_path[256];
extern char hekate_dump_prefix[256];


typedef struct
{
	int state_id;
	
	bool boot0_is_from_hekate;
	bool pkg2_is_from_hekate;
	
	int progress;
	int step_result;
	bool step_completed;
	bool thread_started;
	
	int upload_result;
	char upload_return[256];
	
	hactool_ctx_t tool_ctx;
	nca_ctx_t nca_ctx;
	
#ifdef LOGGING_ENABLED
	char log_buffer[256];
#endif
	
} application_ctx;



char* get_hekate_dump_prefix(void);

void prepend_hdp(char* suffix, char* dest);

/**
 * @brief Creates and starts the function func in a separate thread; the thread has a 0x20000 size stack, a priority of 0x2C, and is on the same core
 * 
 * @param func Function pointer for the function to run, it should take an application_ctx as an argument
 * 
 * @return A pointer to the newly created thread. Be sure to call threadClose and free once it has completed
 */
Thread* util_thread_func(void (*func)(application_ctx*), application_ctx* appstate);

/**
 * @brief The function to actually be threaded, this will run the func
 * 
 * @param arg Pointer to all the arguments to the function
 */
// void util_thread_wrapper(void* args);
void thread_dummy_run(application_ctx* appstate);
void thread_dummy(void* args);
void thread_tester(void* args);

/**
 * @brief Reads 4 bytes from targetfile and returns their value as a little endian, unsigned 32-bit integer
 * 
 * @param targetfile The file to read from
 * 
 * @return Unsigned 32-bit integer composed of the read bytes, in little endian
 */
u32 read_u32_le(FILE* targetfile);

/**
 * @brief Reads 4 bytes from targetfile and returns their value as a big endian, unsigned 32-bit integer
 * 
 * @param targetfile The file to read from
 * 
 * @return Unsigned 32-bit integer composed of the read bytes, in big endian
 */
u32 read_u32_be(FILE* targetfile);

/**
 * @brief Opens the key file, creating it if it does not already exist and doing nothing if it is already open
 * 
 * @return Pointer to the keyfile unless it is already open
 */
FILE* safe_open_key_file(void);

/**
 * @brief Initializes hactool using the keyfile to make sure all the ctxs are up to date; use this to refresh before any hactool-based interactions
 * 
 * @param appstate The state of the application, used for the tool_ctx and nca_ctx
 */
void hactool_init(application_ctx* appstate);

/**
 * @brief Opens the debug log file, writes log_text to it, and flushes/closes it + puts the logged line into the log buffer
 * 
 * @param appstate The state of the application, used to store most recent logged line into buffer
 * @param print_text The text to log
 * @param ... Format specifiers (such as printf)
 */
void debug_log_toscreen(application_ctx* appstate, char* log_text, ...);

/**
 * @brief Opens the debug log file, writes log_text to it, and flushes/closes it
 * 
 * @param print_text The text to log
 * @param ... Format specifiers (such as printf)
 */
void debug_log(char* log_text, ...);

FILE* safe_fopen(const char* filepath, char* mode);

void util_hold_appstate(application_ctx* appstate);

void fatal_error(char* err_text, ...);

#endif