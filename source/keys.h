#ifndef KEYS_H
#define KEYS_H

#include <mbedtls/sha256.h>

#include "util.h"

#include "settings.h"


extern const char nokey[6];

extern const char ZERO_KEY[0x100];

//These are the names of keys we have to pull out individually
extern const char KEY_NAMES[0x16][32];

extern const int KEY_SIZES[0x16];

//These are the names of keys we get in sets, ie master_key_xx
extern const char KEYSET_NAMES[0x0B][32];

extern const int KEYSET_SIZES[0x0B];

extern const char KEY_HASHES[0x16][32];

//Credit for these goes to SciresM (https://raw.githubusercontent.com/Atmosphere-NX/Atmosphere/master/fusee/fusee-secondary/src/key_derivation.c)
//but credit for the idea to use them goes to @Stay off my cock#6239 (nickname Shadów) on the reswitched Discord
//As of right now, only 0 - 4 are used but there will be more in future firmwares
extern const char KEYBLOB_SEEDS[0x20][0x10];

extern const char rsa_kek_seed_3[0x10];
extern const char rsa_kek_mask_0[0x10];

extern char hekate_tsecdump_old_path_full[512];
extern char hekate_tsecdump_new_path_full[512];
extern char hekate_fusedump_path_full[512];



/**
 * @brief Attempts to find the key of size keysize within data of size datasize, using the sha256 of the key (keyhash) and puts the result into resultkey
 * 
 * @param data The data to search within which supposedly contains the key
 * @param keyhash SHA256 of the key
 * @param keysize How long, in bytes, the key is (should be from KEY_SIZES or KEYSET_SIZES)
 * @param datasize Size, in bytes, of data to search
 * @param resultkey Place to put result, should be keysize * 2 large. Will be hex version of the destination key if it was found, "nokey" otherwise
 */
void find_via_hash(char* data, const char* keyhash, int keysize, int datasize, char* resultkey);

/**
 * @brief Takes the data in rawkey, of size keysize, and creates a hex version of it in resultkey
 * 
 * @param rawkey Bytes of keydata
 * @param keysize Number of bytes of keydata (should be from KEY_SIZES or KEYSET_SIZES)
 * @param resultkey Pointer to put resulting hex version of the key, should be keysize * 2 bytes large
 */
void hex_of_key(char* rawkey, int keysize, char* resultkey);

/**
 * @brief Add the key of name keyname with data keycontent to the keyfile
 * 
 * @param keyname Name of the key (should be from KEY_NAMES)
 * @param keycontent The actual key, represented in hex
 */
void add_to_key_file(const char* keyname, char* keycontent);

/**
 * @brief Add the key of name keyname with data keycontent to the keyfile, without attempting to open the keyfile
 * 
 * @param keyname Name of the key (should be from KEY_NAMES)
 * @param keycontent The actual key, represented in hex
 */
void add_to_key_file_no_open(const char* keyname, char* keycontent);

/**
 * @brief Add the key of name keyname with data keycontent to the keyfile, with a specified size (for use when null-terminators are not in place)
 * 
 * @param keyname Name of the key (should be from KEY_NAMES)
 * @param keycontent The actual key, represented in hex
 * @param keysize Size in bytes of the key (should be from KEY_SIZES or KEYSET_SIZES)
 */
void add_to_key_file_sized(const char* keyname, char* keycontent, int keysize);

/**
 * @brief Add the key of name keyname with data keycontent to the keyfile, with a specified size and index (for use with keysets)
 * 
 * @param keyname Name of the key (should be from KEYSET_NAMES)
 * @param keycontent The actual key, represented in hex
 * @param keysize Size in bytes of the key (should be from KEYSET_SIZES)
 * @param keyindex An index from 0x00 to 0x1F to append to keyname
 */
void add_to_key_file_sized_indexed(const char* keyname, char* keycontent, int keysize, int keyindex);

/**
 * @brief A helper function which combines the functionality of find_via_hash and add_to_key_file
 * 
 * @param data Where to search for the key
 * @param keyid The identifier of the key, can be found by looking at KEY_NAMES or KEY_SIZES
 * @param datasize Size, in bytes, of data to search
 */
void find_and_add_key(char* data, int keyid, int datasize);

/**
 * @brief Adds alls the keys contained within keyset_array to the keyfile with the info for keyset keyset_id
 * 
 * @param keyset_array Array containing the content of every key in the keyset, if a key is empty it will not be added
 * @param keyset_id The identifier of the keyset, can be found by looking at KEYSET_NAMES or KEYSET_SIZES
 */
void add_keyset(char** keyset_array, int keyset_id);

/**
 * @brief Adds alls the keys contained within keyset_key_area_array[key_area_id] to the keyfile with the info for keyset keyset_id
 * 
 * @param keyset_key_area_array Array containing the content of every key_area key, if a key is empty it will not be added
 * @param keyset_id The identifier of the keyset, can be found by looking at KEYSET_NAMES or KEYSET_SIZES
 * @param key_area_id Which key area to draw keys from; either 0, 1, or 2 (application, ocean, or system)
 */
void add_keyset_key_area(char** keyset_key_area_array, int keyset_id, int key_area_id);

/**
 * @brief Reads from the dumped tsec_keys and sbk from hekate and puts them in the keyfile
 */
void get_tsec_sbk(void);

/**
 * @brief Updates the keyfile with the relevant keys for the stage from keyset
 * 
 * @param stage Specifies what keys should be added, different keys are ready at different parts of runtime
 * @param keyset The application's keyset
 */
void update_keyfile(int stage, nca_keyset_t* keyset);

#endif