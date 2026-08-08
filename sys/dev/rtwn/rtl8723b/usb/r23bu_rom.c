#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/linker.h>
#include <sys/kdb.h>

#include <net/if.h>
#include <net/ethernet.h>
#include <net/if_media.h>

#include <net80211/ieee80211_var.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include "usbdevs.h"

#include <dev/rtwn/if_rtwnvar.h>
#include <dev/rtwn/if_rtwn_nop.h>

#include <dev/rtwn/usb/rtwn_usb_var.h>
#include <dev/rtwn/usb/rtwn_usb_attach.h>

#include <dev/rtwn/rtl8192c/r92c.h>
#include <dev/rtwn/rtl8192c/r92c_reg.h>

#include <dev/rtwn/rtl8192e/r92e.h>

#include <dev/rtwn/rtl8812a/r12a.h>

#include <dev/rtwn/rtl8723b/usb/r23bu.h>
#include <dev/rtwn/rtl8723b/r23b_priv.h>
#include <dev/rtwn/rtl8723b/r23b_rom_image.h>
#include <dev/rtwn/rtl8723b/r23b_var.h>
#include <dev/rtwn/rtl8723b/r23b_reg.h>

#include <dev/rtwn/rtl8812a/r12a_tx_desc.h>

#include <dev/rtwn/rtl8192c/usb/r92cu.h>

#include <dev/rtwn/rtl8821a/usb/r21au.h>

#include <dev/rtwn/rtl8812a/r12a_reg.h>

#include <dev/rtwn/if_rtwn_debug.h>

void
r23bu_parse_rom(struct rtwn_softc *sc, uint8_t *buf)
{
	struct r23b_rom *rom = (struct r23b_rom *)buf;

	r23b_parse_rom(sc, buf);
	IEEE80211_ADDR_COPY(sc->sc_ic.ic_macaddr, rom->usb_rom.macaddr);
}
