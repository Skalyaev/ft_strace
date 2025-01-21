#include "../include/header.h"

extern t_strace data;

byte bye() {

    if(data.target) free(data.target);
    return data.code;
}
