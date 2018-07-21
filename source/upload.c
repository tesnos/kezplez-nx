#include "upload.h"


CURL* curl = NULL;


static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if(mem->memory == NULL) {
		/* out of memory! */ 
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

void upload_init()
{
	socketInitializeDefault();
}

void upload_keyfile(application_ctx* appstate)
{
	CURLcode res = CURLE_OK;
	
	struct MemoryStruct chunk;
	char* data_to_post;
	
	chunk.memory = malloc(1);
	chunk.size = 0;
	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	
	if (curl)
	{
		curl_easy_setopt(curl, CURLOPT_URL, "https://hastebin.com/documents");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "no-agent/2.0");
		
		keyfile = fopen(keyfile_path, FMODE_READ);
		fseek(keyfile, 0, SEEK_END);
		int keyfilesize = ftell(keyfile);
		fseek(keyfile, 0, SEEK_SET);
		data_to_post = malloc(keyfilesize);
		fread(data_to_post, keyfilesize, 1, keyfile);
		fclose(keyfile);
		
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data_to_post);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) keyfilesize);
		res = curl_easy_perform(curl);
		
		appstate->upload_result = res;
		if (chunk.size < 256) { strncpy(appstate->upload_return, chunk.memory, chunk.size); }
		else { strncpy(appstate->upload_return, chunk.memory, 256); }
		
		free(data_to_post);
	}
}

void upload_exit()
{
	if (curl)
	{
		curl_easy_cleanup(curl);
		free(chunk.memory);
	}
	
	curl_global_cleanup();
	
	socketExit();
}