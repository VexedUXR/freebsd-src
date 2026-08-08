#ifndef R23B_VAR_H
#define R23B_VAR_H

#include <dev/rtwn/rtl8723b/r23b_rom_image.h>
#include <dev/rtwn/rtl8192e/r92e_var.h>

/* XXX If it's only r92e then switch to that. */
struct r23b_softc {
	struct r92e_softc super;

	uint8_t bt_antnum;
};

#endif
