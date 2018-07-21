#ifndef GUI_H
#define GUI_H

#include <stdbool.h>
#include <switch.h>

#include "graphics.h"
#include "util.h"

//Format in hex is      0xAABBGGRR
#define CLEAR_COL       0xFFFFE0E0
#define COL_BLUE        0xFFEE7129
#define COL_GREEN       0xFF00FF00
#define COL_YELLOW      0xFF00FFFF
#define COL_ORANGE      0xFF00A5FF
#define COL_RED         0xFF0000FF
#define COL_VIOLET      0xFF800080
#define COL_MAGENTA     0xFFFF00FF
#define COL_CYAN        0xFFFFFF00
#define COL_WHITE       0xFFFFFFFF
#define COL_BLACK       0xFF000000
#define COL_LIGHTGREY   0xFFC7C7C7

#define FLAG_COLORS_NUM 6

u32 gui_selection_pulse_color(void);

void gui_init(void);

void gui_fillscreen(u32 fillcolor);

void gui_clearscreen(void);

void gui_beginframe(void);

void gui_drawframe(application_ctx* appstate);

void gui_draw_link(char* curl_resp);

void gui_draw_doneinfo(void);

void gui_draw_begininfo(void);

void gui_endframe(void);

void gui_blankframe(void);

void gui_exit(void);

#endif