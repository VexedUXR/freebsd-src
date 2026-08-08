#ifndef R23BU_ROM_IMAGE_H
#define R23BU_ROM_IMAGE_H

struct r23bu_rom {
	uint8_t reserved1[52];
	uint16_t vid;
	uint16_t pid;
	uint8_t reserved2[3];
	uint8_t macaddr[IEEE80211_ADDR_LEN];
	uint8_t reserved3[243];
} __packed;

#endif /* R23BU_ROM_IMAGE_H */
