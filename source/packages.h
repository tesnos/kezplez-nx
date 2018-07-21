#ifndef PACKAGES_H
#define PACKAGES_H

#include <sys/stat.h>

#include "hactool/packages.h"
#include "hactool/pki.h"

#include "keys.h"
#include "util.h"


#define BOOT0_SIZE 0x400000

#define PKG11_REALBEGIN 0x100000
#define PKG11_SIZE 0x40000

#define BCPKG_21_SIZE 0x800000
#define PKG21_BEGIN 0x4000
#define PKG21_SIZE (BCPKG_21_SIZE - PKG21_BEGIN)


//package1
extern const char boot0_path[];
extern const char package1_dir_path[];
extern const char package1_path[];
extern const char hekate_boot0_path[];

//package2
extern const char bcpkg_21_path[];
extern const char package2_dir_path[];
extern const char package2_path[];


extern const char hekate_package2_decrypted_path[];
extern const char package2_decrypted_path[];

extern const char hekate_package2_ini1_path[];
extern const char package2_ini1_path[];
extern const char package2_ini1_dir_path[];

extern const char hekate_package2_kernel_path[];
extern const char package2_kernel_path[];


/**
 * @brief Dump a BIS partition from the system flash to the sd card
 * 
 * @param filepath Place to put the dump on the sd card
 * @param partition_id ID of the partition to dump, list can be found at http://switchbrew.org/index.php?title=Flash_Filesystem
 */
void dump_bis_partition(const char* filepath, u32 partition_id);

/**
 * @brief Dumps BOOT0 to the sd card or copies the version dumped from hekate
 * 
 * @param appstate State of the application, is used to store if the dump is from hekate
 */
void dump_boot0(application_ctx* appstate);

/**
 * @brief Dumps BCPKG_21_NormalMain to the sd card or copies the files dumped from hekate
 * 
 * @param appstate State of the application, is used to store if the dump is from hekate
 */
void dump_bcpkg_21(application_ctx* appstate);

/**
 * @brief Extracts package2 from BCPKG_21_NormalMain if it was dumped
 * 
 * @param appstate State of the application, is used to check if the dump is from hekate
 */
void extract_package2(application_ctx* appstate);

/**
 * @brief Extracts package1 in its encrypted form from BOOT0
 * 
 * @param appstate State of the application
 */
void extract_package1_encrypted(application_ctx* appstate);

/**
 * @brief Extracts package1 in its encrypted form from BOOT0, but this time the real version
 * 
 * @param appstate State of the application
 */
void extract_package1_encrypted_butagain(application_ctx* appstate);

/**
 * @brief Decrypt package1 and place its contents in their own directory
 * 
 * @param appstate State of the application, is used for the tool_ctx
 */
void decrypt_package1(application_ctx* appstate);

/**
 * @brief If not dumped from hekate then decrypted all of package2, else just extract ini1 from hekate dump
 * 
 * @param appstate State of the application, is used for the tool_ctx
 */
void extract_package2_contents(application_ctx* appstate);

#endif