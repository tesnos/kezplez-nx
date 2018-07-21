#ifndef KIP_H
#define KIP_H

#include "util.h"
#include "keys.h"


extern const char spl_path[256];
extern const char decompressed_spl_path[256];

extern const char FS_path[256];
extern const char decompressed_FS_path[256];


/**
 * @brief Decompresses BLZ compressed data within has_compdata of size compdata_size starting at compdata_off and storing the size of the decompressed data in decompdata_size before returning a pointer to the decompressed data
 * 
 * @param has_compdata File which contains the BLZ compressed data
 * @param compdata_off Offset from the beginning of has_compdata where the compressed data is
 * @param compdata_size Size of the compressed data in bytes
 * @param decompdata_size Place to store the size of the decompressed data for use later
 * 
 * @return Pointer to decompressed data. Free this once done with it!!
 */
char* blz_decompress(FILE* has_compdata, u32 compdata_off, u32 compdata_size, int* decompdata_size);

/**
 * @brief Decompresses the .text, .rodata, and .data of kipfile and returns a pointer to the full decompressed data, storing the size of it in kipsize
 * 
 * @param kipfile Kernel Initial Process file, obtained from package2's INI1 portion
 * @param kipsize Place to store the size of the decompressed kip
 * 
 * @return Pointer to full decompressed data. Free this once done with it!!
 */
char* kip_get_full(FILE* kipfile, int* kipsize);

/**
 * @brief Decompresses both spl and FS kip1s and saves their decompressed versions
 * 
 * @param appstate State of the application 
 */
void extract_kip1s(application_ctx* appstate);

/**
 * @brief Finds relevant keys within the decompressed version of spl
 * 
 * @param appstate State of the application 
 */
void derive_part2_spl(application_ctx* appstate);

/**
 * @brief Finds relevant keys within the decompressed version of FS
 * 
 * @param appstate State of the application 
 */
void derive_part2_FS(application_ctx* appstate);

#endif