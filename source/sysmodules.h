#ifndef SYSMODULES_H
#define SYSMODULES_H

#include <dirent.h>

#include "keys.h"
#include "nca.h"
#include "pki.h"
#include "util.h"

#define ETICKET_TID 0x0100000000000033

void get_eticket_rsa_kek(application_ctx* appstate);

#endif