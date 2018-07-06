#include <stdlib.h>
#include <switch.h>
#include <math.h>

#include "lodepng.h"
#include "font.h"

#define FONT_COL_DARK   0xFF000000
#define FONT_COL_LIGHT  0xFFFFFFFF
#define THEME_COL_LIGHT 0xFFEBEBEB
#define THEME_COL_DARK  0xFF2D2D2D

struct Graphics_Image
{
	u32* ptr;
	unsigned int width;
	unsigned int height;
};

void update_framebuf_ptr(void);

struct Graphics_Image* graphics_loadpng(char* filename);

void graphics_get_dimensions(u32* width, u32* height);

u32 graphics_get_theme_color(void);
u32 graphics_get_theme_color_font(void);

u32 graphics_get_width(void);
u32 graphics_get_height(void);

void graphics_init(void);

void graphics_beginframe(void);

void graphics_setpixel(int x, int y, u32 rgba);

void graphics_setpixelpos(int pos, u32 rgba);

void graphics_draw_image(int x, int y, struct Graphics_Image* imgstructptr);

void graphics_draw_image_scaled(int x, int y, struct Graphics_Image* imgstructptr, float scale);

void graphics_draw_rect(int x, int y, int width, int height, u32 color);

void graphics_draw_rect_outlined(int x, int y, int width, int height, u32 color, u32 outline_color, int outline_width);

void graphics_draw_text(int x, int y, u32 rgba, const char* text);

void graphics_endframe(void);

void graphics_freeimage(struct Graphics_Image* imgstructptr);

void graphics_exit(void);