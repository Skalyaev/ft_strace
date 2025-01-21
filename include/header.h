#ifndef HEADER_H
#define HEADER_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>

#include "define.h"
#include "struct.h"

void getargs(const int ac, char** const av);
byte init();
byte bye();

#endif
