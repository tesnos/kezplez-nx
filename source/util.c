#include "util.h"

Thread* util_thread_func(void (*func)(void *))
{
	//*done = false;
	Thread* func_thread = malloc(sizeof(Thread));
	
	threadCreate(func_thread, func, NULL, 0x20000, 0x2C, -2);
	threadStart(func_thread);
	
	return func_thread;
	//threadWaitForExit(func_thread);
	//threadClose(func_thread);
	
	//*done = true;
}