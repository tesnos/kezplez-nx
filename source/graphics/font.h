#include <ft2build.h>
#include FT_FREETYPE_H
#include <switch.h>

#define FONT_FACES_MAX PlSharedFontType_Total

//The following code was adapted from nx-hbmenu and Checkpoint
//Kudos to all the people who are willing to figure out how fonts work, because I am not one of them.
/**

Copyright 2017-2018 nx-hbmenu Authors

Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee is hereby granted,
provided that the above copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT,
OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

**/

u32* font_framebuf_ptr;
u32 font_framebuf_width;

typedef struct {
    u8 width, height;
    int8_t posX, posY, advance, pitch;
    const u8* data;
} glyph_t;


void font_setpixel(int x, int y, u32 rgba);

void font_drawtext(u32 font, u32 x, u32 y, u32 rgba, const char* text);

void font_drawtext_truncate(u32 font, u32 x, u32 y, u32 rgba, const char* text, u32 max_width, const char* end_text);

void font_get_text_dimensions(u32 font, const char* text, u32* width_out, u32* height_out);

bool font_init(void);

void font_exit();