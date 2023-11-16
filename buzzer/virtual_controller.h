#ifndef BUZZER_VIRTUAL_CONTROLLER_H
#define BUZZRE_VIRTUAL_CONTROLLER_H

#include <sys/types.h>
#include <unistd.h>

void bz_vctrl_init(int ep1, int ep2);

void bz_vctrl_start_record();

#endif