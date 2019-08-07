#ifndef GILGIL_H
#define GILGIL_H
#include <stdint.h>
struct gilethernet{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;

};
struct gilarp
{
    uint16_t Htype;
    uint16_t Ptype;
    uint8_t Hsize;
    uint8_t Psize;
    uint16_t OPcode;
    uint8_t Smac[6];
    uint8_t Sip[4];
    uint8_t Dmac[6];
    uint8_t Dip[4];
};


#endif // GILGIL_H

