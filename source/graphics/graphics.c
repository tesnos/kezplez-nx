#include "graphics.h"

u32* framebuf_ptr;
u32 framebuf_width, framebuf_height;
ColorSetId themeid;

void update_framebuf_ptr()
{
	framebuf_ptr = (u32*) gfxGetFramebuffer(&framebuf_width, &framebuf_height);
	font_framebuf_ptr = framebuf_ptr;
	font_framebuf_width = framebuf_width;
}

struct Graphics_Image* graphics_loadpng(char* filename)
{
	struct Graphics_Image* imgstructptr = malloc(sizeof(struct Graphics_Image));
	lodepng_decode32_file((unsigned char**) &imgstructptr->ptr, &imgstructptr->width, &imgstructptr->height, filename);
	return imgstructptr;
}

void graphics_get_dimensions(u32* widthptr, u32* heightptr)
{
	*widthptr = framebuf_width;
	*heightptr = framebuf_height;
}

u32 graphics_get_theme_color()
{
	if (themeid == ColorSetId_Light)
	{
		return THEME_COL_LIGHT;
	}
	else if (themeid == ColorSetId_Dark)
	{
		return THEME_COL_DARK;
	}
	
	return THEME_COL_LIGHT;
}

u32 graphics_get_theme_color_font()
{
	if (themeid == ColorSetId_Light)
	{
		return FONT_COL_DARK;
	}
	else if (themeid == ColorSetId_Dark)
	{
		return FONT_COL_LIGHT;
	}
	
	return FONT_COL_DARK;
}

u32 graphics_get_width() { return framebuf_width; }
u32 graphics_get_height() { return framebuf_height; }

void graphics_init()
{
	//Services
	setsysInitialize();
	gfxInitResolutionDefault();
	gfxInitDefault();
	gfxConfigureAutoResolutionDefault(true);
	plInitialize();
	
	font_init();
	setsysGetColorSetId(&themeid);
	update_framebuf_ptr();
}

void graphics_beginframe()
{
	update_framebuf_ptr();
}

void graphics_setpixel(int x, int y, u32 rgba)
{
	int framebuf_targetpos = (y * framebuf_width) + x;
	framebuf_ptr[framebuf_targetpos] = rgba;
}

void graphics_setpixelpos(int pos, u32 rgba)
{
	framebuf_ptr[pos] = rgba;
}

void graphics_draw_image(int x, int y, struct Graphics_Image* imgstructptr)
{
	for (int cury = y; cury < y + imgstructptr->height; cury++)
	{
		for (int curx = x; curx < x + imgstructptr->width; curx++)
		{
			int img_targetpos = ((cury - y) * imgstructptr->width) + (curx - x);
			if ((imgstructptr->ptr[img_targetpos] & 0xFF000000) != 0) { graphics_setpixel(curx, cury, imgstructptr->ptr[img_targetpos]); }
		}
	}
}

void graphics_draw_image_scaled(int x, int y, struct Graphics_Image* imgstructptr, float scale)
{
	float increment = 1 / scale;
	for (float cury = y; cury < y + imgstructptr->height; cury += increment)
	{
		for (float curx = x; curx < x + imgstructptr->width; curx += increment)
		{
			int pixelposx = ((curx - x) / increment) + x;
			int pixelposy = ((cury - y) / increment) + y;
			int img_targetpos = round(((cury - y) * imgstructptr->width) + (curx - x));
			if ((imgstructptr->ptr[img_targetpos] & 0xFF000000) != 0) { graphics_setpixel(pixelposx, pixelposy, imgstructptr->ptr[img_targetpos]); }
		}
	}
}

void graphics_draw_rect(int x, int y, int width, int height, u32 color)
{
	for (int cury = y; cury < y + height; cury++)
	{
		for (int curx = x; curx < x + width; curx++)
		{
			graphics_setpixel(curx, cury, color);
		}
	}
}

void graphics_draw_rect_outlined(int x, int y, int width, int height, u32 color, u32 outline_color, int outline_width)
{
	for (int cury = y; cury < y + height; cury++)
	{
		for (int curx = x; curx < x + width; curx++)
		{
			if (((curx - x) < outline_width || (curx - x) > width - outline_width) || ((cury - y) < outline_width || (cury - y) > height - outline_width))
			{
				graphics_setpixel(curx, cury, outline_color);
				continue;
			}
			graphics_setpixel(curx, cury, color);
		}
	}
}

void graphics_draw_text(int x, int y, u32 rgba, const char* text)
{
	font_drawtext(5, x, y, rgba, text);
}

void graphics_endframe()
{
	//DrawText(5, 20, 20, 0xFF000000, "hello world");
	gfxFlushBuffers();
	gfxSwapBuffers();
	gfxWaitForVsync();
}

void graphics_freeimage(struct Graphics_Image* imgstructptr)
{
	free(imgstructptr->ptr);
	free(imgstructptr);
}

void graphics_exit()
{
	font_exit();

	plExit();
	gfxExit();
	setsysExit();
}