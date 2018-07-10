#include "gui.h"

u32 screenwidth, screenheight;
struct Graphics_Image* testimg;

u32 flag_colors[FLAG_COLORS_NUM] = {COL_RED, COL_ORANGE, COL_YELLOW, COL_GREEN, COL_BLUE, COL_VIOLET};

void gui_init()
{
	graphics_init();
	//flag_colors_num = 6;
	//flag_colors[flag_colors_num] = {COL_RED, COL_ORANGE, COL_YELLOW, COL_GREEN, COL_BLUE, COL_VIOLET};
	testimg = graphics_loadpng("/bluegrad.png");
}

void gui_fillscreen(u32 fillcolor)
{
	graphics_draw_rect(0, 0, screenwidth, screenheight, fillcolor);
}

void gui_clearscreen()
{
	gui_fillscreen(graphics_get_theme_color());
	
	for (int i = 0; i < FLAG_COLORS_NUM; i++)
	{
		graphics_draw_rect(0, i * (screenheight / FLAG_COLORS_NUM), screenwidth, (screenheight / FLAG_COLORS_NUM), flag_colors[i]);
	}
}

void gui_beginframe()
{
	graphics_beginframe();
	screenwidth = graphics_get_width();
	screenheight = graphics_get_height();
	gui_clearscreen();
}

void gui_drawframe(int appstate)
{
	char a[33]; a[32] = 0x00;
	snprintf(a, 32, "%02i", appstate);
	graphics_draw_text(50, 18, graphics_get_theme_color_font(), a);
}

void gui_draw_link(char* curl_resp)
{
	char a[32] = "https://hastebin.com/";
	snprintf(a + 21, 10, "%s", curl_resp);
	graphics_draw_text(50, 150, graphics_get_theme_color_font(), "You may also find your keys at the following link, which will expire in 30 days:");
	graphics_draw_text(50, 220, graphics_get_theme_color_font(), a);
}

void gui_draw_begininfo(void)
{
	graphics_draw_text(50, 80, graphics_get_theme_color_font(), "Press A to begin. This process may take up to 2 minutes, so please patient.\nAs progress is made, the above counter will increment and when it reaches 19 the program has finished.\nIt is expected for the counter to be stuck at 17 for a while.");
}

void gui_draw_doneinfo(void)
{
	graphics_draw_text(50, 80, graphics_get_theme_color_font(), "All keys have been extracted.\nThey are in a file named 'keys.txt' at the root of your sd card.\nPress + to exit.");
}

void gui_endframe()
{
	graphics_endframe();
}

void gui_blankframe()
{
	gui_beginframe();
	gui_endframe();
}

void gui_exit()
{
	graphics_freeimage(testimg);
	graphics_exit();
}