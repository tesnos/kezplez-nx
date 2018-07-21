#include "kips.h"


const char spl_path[256] = "/switch/kezplez-nx/ini1/spl.kip1\0";
const char decompressed_spl_path[256] = "/switch/kezplez-nx/ini1/decomp_spl.kip1\0";

const char FS_path[256] = "/switch/kezplez-nx/ini1/FS.kip1\0";
const char decompressed_FS_path[256] = "/switch/kezplez-nx/ini1/decomp_FS.kip1\0";



//so it turns out I do have to know how to do this now
char* blz_decompress(FILE* has_compdata, u32 compdata_off, u32 compdata_size, int* decompdata_size)
{
	debug_log("reading compressed data into memory...\n");
	u8* compressed = malloc(compdata_size);
	fseek(has_compdata, compdata_off, SEEK_SET);
	fread(compressed, compdata_size, 1, has_compdata);
	
	int total = compdata_off + compdata_size - 0x0C;
	debug_log("obtaining info about compressed data...\n");
	debug_log("compdata_off:%08x, compdata_size:%08x, total:%08x\n", compdata_off, compdata_size, total);
	
	fseek(has_compdata, 0, SEEK_SET);
	fseek(has_compdata, total, SEEK_SET);
	
	int loc = ftell(has_compdata);
	debug_log("loc:%08x\n", loc);
	
	u32 compressed_size = read_u32_le(has_compdata);
	u32 init_index = read_u32_le(has_compdata);
	u32 uncompressed_addl_size = read_u32_le(has_compdata);
	
	loc = ftell(has_compdata);
	debug_log("loc:%08x\n", loc);
	debug_log("compressed_size:%08x, init_index:%08x, uncompressed_addl_size:%08x\n", compressed_size, init_index, uncompressed_addl_size);
	
	debug_log("creating decompression buffer...\n");
	
	int decompressed_size = compressed_size + uncompressed_addl_size;
	*decompdata_size = decompressed_size;
	char* decompressed = malloc(decompressed_size);
	if (compdata_size != compressed_size)
	{
		memcpy(decompressed, compressed + (compdata_size - compressed_size), compressed_size);
	}
	else
	{
		memcpy(decompressed, compressed, compressed_size);
	}
	
	int index = compressed_size - init_index;
	int outindex = decompressed_size;
	debug_log("decompressing...\n");

	while (outindex > 0)
	{
		index--;
		u8 control = (u8) compressed[index];
		for (int i = 0; i < 8; i++)
		{
			if (control & 0x80)
			{
				if (index < 2) { debug_log("ERR: Compression out of bounds! (case 0)\n"); }
				index -= 2;
				int segmentoffset = compressed[index] | (compressed[index + 1] << 8);
				int segmentsize = ((segmentoffset >> 12) & 0xF) + 3;
				segmentoffset = segmentoffset & 0x0FFF;
				segmentoffset += 2;
				if (outindex < segmentsize) { debug_log("ERR: Compression out of bounds! (case 1)\n"); }
				for (int j = 0; j < segmentsize; j++)
				{
					if (outindex + segmentoffset >= decompressed_size) { debug_log("ERR: Compression out of bounds! (case 2)\n"); }
					char data = decompressed[outindex + segmentoffset];
					outindex--;
					decompressed[outindex] = data;
				}
			}
			else
			{
				if (outindex < 1) { debug_log("ERR: Compression out of bounds! (case 3)\n"); }
				outindex--;
				index--;
				decompressed[outindex] = compressed[index];
			}
			control = control << 1;
			control = control & 0xFF;
			if (outindex == 0)
			{
				break;
			}
		}
	}
	
	return decompressed;
}

char* kip_get_full(FILE* kipfile, int* kipsize)
{
	debug_log("reading sizes...\n");
	
	fseek(kipfile, 0x20, SEEK_SET);
	u32 tloc = read_u32_le(kipfile); u32 tsize = read_u32_le(kipfile); u32 tfilesize = read_u32_le(kipfile);
	debug_log("tloc: %08x, tsize: %08x, tfilesize: %08x\n", tloc, tsize, tfilesize);
	
	fseek(kipfile, 0x30, SEEK_SET);
	u32 rloc = read_u32_le(kipfile); u32 rsize = read_u32_le(kipfile); u32 rfilesize = read_u32_le(kipfile);
	debug_log("rloc: %08x, rsize: %08x, rfilesize: %08x\n", rloc, rsize, rfilesize);
	
	fseek(kipfile, 0x40, SEEK_SET);
	u32 dloc = read_u32_le(kipfile); u32 dsize = read_u32_le(kipfile); u32 dfilesize = read_u32_le(kipfile);
	debug_log("dloc: %08x, dsize: %08x, dfilesize: %08x\n", dloc, dsize, dfilesize);

	
	int toff = 0x100;
	int roff = toff + tfilesize;
	int doff = roff + rfilesize;
	debug_log("toff: %08x, roff: %08x, doff: %08x\n", toff, roff, doff);

	fseek(kipfile, 0x18, SEEK_SET);
	int bsssize = read_u32_le(kipfile);
	debug_log("bss-size: %08x\n", bsssize);

	
	int t_dsize, r_dsize, d_dsize;
	debug_log("decompressing sections (t)...\n");
	char* text = blz_decompress(kipfile, toff, tfilesize, &t_dsize);
	debug_log("decompressing sections (r)...\n");
	char* ro   = blz_decompress(kipfile, roff, rfilesize, &r_dsize);
	debug_log("decompressing sections (d)...\n");
	char* data = blz_decompress(kipfile, doff, dfilesize, &d_dsize);
	
	
	debug_log("joining sections...\n");
	char* full = malloc(t_dsize + r_dsize + d_dsize);
	
	memcpy(full, text, t_dsize);
	memcpy(full + t_dsize, ro, r_dsize);
	memcpy(full + t_dsize + r_dsize, data, d_dsize);
	
	debug_log("cleaning up...\n");
	free(text); free(ro); free(data);
	*kipsize = t_dsize + r_dsize + d_dsize;
	
	return full;
}

void extract_kip1s(application_ctx* appstate)
{
	debug_log("Decompressing spl kip1...\n");
	
	FILE* spl_f = fopen(spl_path, FMODE_READ);
	FILE* decomp_spl_f = fopen(decompressed_spl_path, FMODE_WRITE);
	int spl_size;
	char* spl_data = kip_get_full(spl_f, &spl_size);
	fwrite(spl_data, spl_size, 1, decomp_spl_f);
	
	debug_log("Result: spl_size == %08x\n", spl_size);
	
	free(spl_data);
	fclose(decomp_spl_f);
	fclose(spl_f);
	
	debug_log("Decompressing FS kip1...\n");
	
	FILE* FS_f = fopen(FS_path, FMODE_READ);
	FILE* decomp_FS_f = fopen(decompressed_FS_path, FMODE_WRITE);
	int FS_size;
	char* FS_data = kip_get_full(FS_f, &FS_size);
	fwrite(FS_data, FS_size, 1, decomp_FS_f);
	
	debug_log("Result: FS_size == %08x\n", spl_size);
	
	free(FS_data);
	fclose(decomp_FS_f);
	fclose(FS_f);
}

void derive_part2_spl(application_ctx* appstate)
{
	debug_log("Opening decompressed spl kip1...\n");
	
	FILE* SPL_f = fopen(decompressed_spl_path, FMODE_READ);
	
	fseek(SPL_f, 0, SEEK_END);
	int SPL_SIZE = ftell(SPL_f);
	fseek(SPL_f, 0, SEEK_SET);
	
	debug_log("SPL_SIZE == %08x\n", SPL_SIZE);
	
	char* SPL_DATA = malloc(SPL_SIZE);
	fread(SPL_DATA, SPL_SIZE, 1, SPL_f);
	fclose(SPL_f);
	
	debug_log("Adding %s to the key file\n", "aes_key_generation_source");
	find_and_add_key(SPL_DATA, 0x07, SPL_SIZE);  //aes_key_generation_source
	
	free(SPL_DATA);
}

void derive_part2_FS(application_ctx* appstate)
{
	debug_log("Opening decompressed FS kip1...\n");
	
	FILE* FS_f = fopen(decompressed_FS_path, FMODE_READ);
	
	fseek(FS_f, 0, SEEK_END);
	int FS_SIZE = ftell(FS_f);
	fseek(FS_f, 0, SEEK_SET);
	
	debug_log("FS_SIZE == %08x\n", FS_SIZE);
	
	char* FS_DATA = malloc(FS_SIZE);
	fread(FS_DATA, FS_SIZE, 1, FS_f);
	fclose(FS_f);
	
	debug_log("Adding %s to the key file\n", "key_area_key_application_source");
	find_and_add_key(FS_DATA, 0x09, FS_SIZE);  //key_area_key_application_source
	debug_log("Adding %s to the key file\n", "key_area_key_ocean_source");
	find_and_add_key(FS_DATA, 0x0A, FS_SIZE);  //key_area_key_ocean_source
	debug_log("Adding %s to the key file\n", "key_area_key_system_source");
	find_and_add_key(FS_DATA, 0x0B, FS_SIZE);  //key_area_key_system_source
	debug_log("Adding %s to the key file\n", "sd_card_kek_source");
	find_and_add_key(FS_DATA, 0x0C, FS_SIZE);  //sd_card_kek_source
	debug_log("Adding %s to the key file\n", "sd_card_save_key_source");
	find_and_add_key(FS_DATA, 0x0D, FS_SIZE);  //sd_card_save_key_source
	debug_log("Adding %s to the key file\n", "sd_card_nca_key_source");
	find_and_add_key(FS_DATA, 0x0E, FS_SIZE);  //sd_card_nca_key_source
	debug_log("Adding %s to the key file\n", "header_kek_source");
	find_and_add_key(FS_DATA, 0x0F, FS_SIZE);  //header_kek_source
	debug_log("Adding %s to the key file\n", "header_key_source");
	find_and_add_key(FS_DATA, 0x10, FS_SIZE);  //header_key_source
	
	free(FS_DATA);
}