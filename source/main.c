//library includes
#include <switch.h>
#include <stdbool.h>
#include <lz4.h>

//hactool includes
#include "hactool/pki.h"
#include "hactool/types.h"
#include "hactool/nca.h"
#include "hactool/extkeys.h"

//local includes
#include "graphics/gui.h"
#include "util.h"

//internal definitions
int BOOT0_SIZE = 0x400000;
int PKG11_OFF;
int PKG11_REALBEGIN = 0x100000;
int PKG11_SIZE= 0x40000;
char BOOT0_DATA[BOOT0_SIZE];
char PKG11_DATA[PKG11_SIZE];

int BCPKG_21_SIZE = 0x800000;
int PKG21_BEGIN = 0x4000;
int PKG21_SIZE = BCPKG_21_SIZE - PKG21_BEGIN;
char BCPKG_21_DATA[BCPKG_21_SIZE];
char PKG21_DATA[PKG21_SIZE];

int numkeys = 29;

char KEY_NAMES[29][32] = {
	"keyblob_mac_key_source\0", //Key 0
	"keyblob_key_source_00\0", //Key 1
	"keyblob_key_source_01\0", //Key 2
	"keyblob_key_source_02\0", //Key 3
	"keyblob_key_source_03\0", //Key 4
	"keyblob_key_source_04\0", //Key 5
	"master_key_source\0", //Key 6
	"master_key_00\0", //Key 7
	"master_key_01\0", //Key 8
	"master_key_02\0", //Key 9
	"master_key_03\0", //Key 10
	"master_key_04\0", //Key 11
	"package1_key_00\0", //Key 12
	"package1_key_01\0", //Key 13
	"package1_key_02\0", //Key 14
	"package1_key_03\0", //Key 15
	"package1_key_04\0", //Key 16
	"package2_key_source\0", //Key 17
	"aes_kek_generation_source\0", //Key 18
	"aes_key_generation_source\0", //Key 19
	"titlekek_source\0", //Key 20
	"key_area_key_application_source\0", //Key 21
	"key_area_key_ocean_source\0", //Key 22
	"key_area_key_system_source\0", //Key 23
	"header_kek_source\0", //Key 24
	"header_key_source\0", //Key 25
	"sd_card_kek_source\0", //Key 26
	"sd_card_save_key_source\0", //Key 27
	"sd_card_nca_key_source" //Key 28
};

char KEY_HASHES[29][64] = {
	"B24BD293259DBC7AC5D63F88E60C59792498E6FC5443402C7FFE87EE8B61A3F0",
	"8A06FE274AC491436791FDB388BCDD3AB9943BD4DEF8094418CDAC150FD73786",
	"2D5CAEB2521FEF70B47E17D6D0F11F8CE2C1E442A979AD8035832C4E9FBCCC4B",
	"61C5005E713BAE780641683AF43E5F5C0E03671117F702F401282847D2FC6064",
	"8E9795928E1C4428E1B78F0BE724D7294D6934689C11B190943923B9D5B85903",
	"95FA33AF95AFF9D9B61D164655B32710ED8D615D46C7D6CC3CC70481B686B402",
	"7944862A3A5C31C6720595EFD302245ABD1B54CCDCF33000557681E65C5664A4",
	"0EE359BE3C864BB0782E1D70A718A0342C551EED28C369754F9C4F691BECF7CA",
	"4FE707B7E4ABDAF727C894AAF13B1351BFE2AC90D875F73B2E20FA94B9CC661E",
	"79277C0237A2252EC3DFAC1F7C359C2B3D121E9DB15BB9AB4C2B4408D2F3AE09",
	"4F36C565D13325F65EE134073C6A578FFCB0008E02D69400836844EAB7432754",
	"75FF1D95D26113550EE6FCC20ACB58E97EDEB3A2FF52543ED5AEC63BDCC3DA50",
	"4543CD1B7CAD7EE0466A3DE2086A0EF923805DCEA6C741541CDDB14F54F97B40",
	"984F1916834540FF3037D65133F374BD9E715DC3B162AAC77C8387F9B22CF909",
	"9E7510E4141AD89D0FB697E817326D3C80F96156DCE7B6903049AC033E95F612",
	"E65C383CDF526DFFAA77682868EBFA9535EE60D8075C961BBC1EDE5FBF7E3C5F",
	"28AE73D6AE8F7206FCA549E27097714E599DF1208E57099416FF429B71370162",
	"21E2DF100FC9E094DB51B47B9B1D6E94ED379DB8B547955BEF8FE08D8DD35603",
	"FC02B9D37B42D7A1452E71444F1F700311D1132E301A83B16062E72A78175085",
	"FBD10056999EDC7ACDB96098E47E2C3606230270D23281E671F0F389FC5BC585",
	"C48B619827986C7F4E3081D59DB2B460C84312650E9A8E6B458E53E8CBCA4E87",
	"04AD66143C726B2A139FB6B21128B46F56C553B2B3887110304298D8D0092D9E",
	"FD434000C8FF2B26F8E9A9D2D2C12F6BE5773CBB9DC86300E1BD99F8EA33A417",
	"1F17B1FD51AD1C2379B58F152CA4912EC2106441E51722F38700D5937A1162F7",
	"1888CAED5551B3EDE01499E87CE0D86827F80820EFB275921055AA4E2ABDFFC2",
	"8F783E46852DF6BE0BA4E19273C4ADBAEE16380043E1B8C418C4089A8BD64AA6",
	"6B2ED877C2C52334AC51E59ABFA7EC457F4A7D01E46291E9F2EAA45F011D24B7",
	"D482743563D3EA5DCDC3B74E97C9AC8A342164FA041A1DC80F17F6D31E4BC01C",
	"2E751CECF7D93A2B957BD5FFCB082FD038CC2853219DD3092C6DAB9838F5A7CC"
};

int KEY_SIZES[29] = {
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x10,
	0x20,
	0x10,
	0x20,
	0x20
};

char keyfilepath[10] = "/keys.txt\0";

int appstate, progress, step_result, fail_result;
FILE* keyfile;
bool step_completed;
Thread* step_thread;


//hactool-based definitions
hactool_ctx_t tool_ctx;
nca_ctx_t nca_ctx;

char* find_via_hash(data, hash, size):
	for i in range(len(data) - size):
		m = hashlib.sha256()
		m.update(data[i : i + size])
		if m.hexdigest() == hash.lower():
			#print "key found"
			return binascii.hexlify(data[i : i + size]).upper()
			#print binascii.hexlify(data[i : i + len(hash)]).upper()
			#print m.hexdigest()
			#break
	
	return ""

void safe_open_key_file()
{
	if (keyfile == NULL)
	{
		keyfile = fopen(keyfilepath, "rb");
		if (keyfile == NULL)
		{
			keyfile = fopen(keyfilepath, "wb");
		}
	}
}

void add_to_key_file(char* keyname, char* keycontent)
{
	safe_open_key_file();
	
	fwrite(keyname, strlen(keyname), 1, keyfile);
	fwrite(" = ", 3, 1, keyfile);
	fwrite(keycontent, strlen(keycontent), 1, keyfile);
	fwrite("\n", 1, 1, keyfile);
	
	fclose(keyfile);
}

void find_and_add_key(char* data, int keyid)
{
	char* key = find_via_hash(data, KEY_HASHES[keyid], KEY_SIZES[keyid]);
	add_to_key_file(KEY_NAMES[keyid], key);
}

void hactool_init()
{
	memset(&tool_ctx, 0, sizeof(tool_ctx));
	tool_ctx.action = ACTION_INFO | ACTION_EXTRACT;
	//key init
	safe_open_key_file();
	
	pki_initialize_keyset(&tool_ctx.settings.keyset, KEYSET_RETAIL);
	extkeys_initialize_keyset(&tool_ctx.settings.keyset, keyfile);
	
	parse_hex_key(nca_ctx.tool_ctx->settings.keygen_sbk, "", 16);
	parse_hex_key(nca_ctx.tool_ctx->settings.keygen_tsec, "", 16);
	
	pki_derive_keys(&tool_ctx.settings.keyset);
	fclose(keyfile);
}

void dump_bis_partition(char* filepath, u32 partition_id)
{
	step_completed = false;
	
	FILE* dumpfile = fopen(filepath, "wb");
	FsStorage partition;
	u64 partition_size, dump_progress, bytes_to_dump;
	
	Result rc = fsOpenBisStorage(&partition, partition_id);
	if (R_FAILED(rc)) { fail_result = rc; step_completed = true; return; }
	
	rc = fsStorageGetSize(&partition, &partition_size);
	if (R_FAILED(rc)) { fail_result = rc; step_completed = true; return; }
	
	size_t dump_buffer_size = 0x10000;
	u8 dump_buffer[dump_buffer_size];
	
	dump_progress = 0;
	while(dump_progress < partition_size)
	{
		if ((partition_size - dump_progress) > dump_buffer_size)
		{
			bytes_to_dump = dump_buffer_size;
		}
		else
		{
			bytes_to_dump = (partition_size - dump_progress);
		}
		
		rc = fsStorageRead(&partition, dump_progress, dump_buffer, bytes_to_dump);
		if (R_FAILED(rc)) { fail_result = rc; step_completed = true; return; }
		
		fwrite(dump_buffer, bytes_to_dump, 1, dumpfile);
		
		dump_progress += bytes_to_dump;
	}
	
	fsStorageClose(&partition);
	fclose(dumpfile);
	
	step_completed = true;
	step_result = rc;
}

void dump_boot0()
{
	dump_bis_partition("/switch/kezplez-nx/boot0.bin", 0);
}

void dump_bcpkg_21()
{
	dump_bis_partition("/switch/kezplez-nx/BCPKG_21_NormalMain.bin", 21);
}

void extract_package2()
{
	step_completed = false;
	
	FILE* BCPKG_21_f = fopen("/switch/kezplez-nx/BCPKG_21_NormalMain.bin", "rb");
	FILE* PKG21_f = fopen("/switch/kezplez-nx/package2.bin", "wb");
	
	fread(BCPKG_21_DATA, BCPKG_21_SIZE, 1, BCPKG_21_f);
	memcpy(PKG21_DATA, BCPKG_21_DATA + PKG21_BEGIN, PKG21_SIZE);
	fwrite(PKG21_DATA, PKG21_SIZE, 1, PKG21_f);
	
	fclose(PKG21_f);
	fclose(BCPKG_21_f);
	
	step_completed = true;
	step_result = 0;
}

void extract_package1_encrypted()
{
	step_completed = false;
	
	FILE* BOOT0_f = fopen("/switch/kezplez-nx/boot0.bin", "rb");
	FILE* PKG11_f = fopen("/switch/kezplez-nx/package1.bin", "wb");
	
	fread(BOOT0_DATA, BOOT0_SIZE, 1, BOOT0_f);
	PK11_OFF = strstr(BOOT0_DATA, "PK11") - BOOT0_DATA;
	memcpy(PKG11_DATA, BOOT0_DATA + PK11_OFF, PKG11_SIZE);
	fwrite(PKG11_DATA, PKG11_SIZE, 1, PKG11_f);
	
	fclose(PKG11_f);
	fclose(BOOT0_f);
	
	step_completed = true;
	step_result = 0;
}

void 


int main(int argc, char** argv)
{
	//app init
	gui_init();
	
	//internal variable inits
	appstate = 0;
	progress = 0;
	fail_result = 0;
	
	//hactool init
	hactool_init();
	
	
	while (appletMainLoop())
	{
		hidScanInput();
		u64 kDown = hidKeysDown(CONTROLLER_P1_AUTO);
		if (kDown & KEY_PLUS) break;
		
		//Beginning
		if (appstate == 0)
		{
			if (kDown & KEY_A)
			{
				appstate = 1;
				step_completed = true;
			}
		}
		
		//After every step, try the next
		if (appstate == 1 && step_completed)
		{
			if (progress > 0)
			{
				threadClose(step_thread);
				free(step_thread);
			}
			
			//check if previous step failed
			if (R_FAILED(step_result) || fail_result != 0)
			{
				appstate = 3;
			}
			else
			{
				progress++;
			}
		}
		
		
		if (appstate == 1 && step_completed)
		{
			if (progress == 1)
			{
				step_thread = util_thread_func(dump_boot0);
			}
			
			if (progress == 2)
			{
				step_thread = util_thread_func(dump_bcpkg_21);
			}
			
			if (progress == 3)
			{
				step_thread = util_thread_func(extract_package2);
			}
			
			if (progress == 4)
			{
				step_thread = util_thread_func(extract_package1_encrypted);
			}
			
			if (progress == 5)
			{
				appstate = 2;
			}
		}
		
		
		gui_beginframe();
		gui_drawframe(progress);
		gui_endframe();
	}
	
	
	gui_exit();
	return 0;
}