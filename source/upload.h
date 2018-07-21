#ifndef UPLOAD_H
#define UPLOAD_H

#include <curl/curl.h>

#include "util.h"

//Taken from the curl examples. Currently does not work because of a lack of https support :(
struct MemoryStruct {
	char *memory;
	size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp);

void upload_init(void);

void upload_keyfile(application_ctx* appstate);

void upload_exit(void);

#endif