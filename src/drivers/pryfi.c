#include "includes.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <stdlib.h>
#include "utils/common.h"
#include "drivers/linux_ioctl.h"
#include "wpa_supplicant_i.h"

#include <linux/if.h>
#include <linux/if_arp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>

#ifdef CONFIG_PRYFI_LOG
#define PRYFI_LOG(...) ((void)wpa_printf(MSG_INFO, __VA_ARGS__))
#else
#define PRYFI_LOG(...) ((void)0)
#endif

#ifndef CONFIG_PRYFI_MAC_CHANGE_DIGITS
// If this way of changing MAC works, the last 3 numbers are changable
// On some devices and situations, the last 5 are. Sometimes all 6.
// Doing just the last 3 here, should be safe-ish.
#define CONFIG_PRYFI_MAC_CHANGE_DIGITS 3
#endif

#define MAX_INTERFACE_COUNT 16
#define MAC_PERSIST_FILENAME "/data/misc/wifi/mac_%s"

static int randseeded = 0;

typedef struct interface_t {
	char ifname[IFNAMSIZ];
	u8 hwaddr_org[ETH_ALEN];
	u8 hwaddr_cur[ETH_ALEN];
	int hwaddr_modified;
	int stored;
	int socket;
} interface;

static interface interfaces[MAX_INTERFACE_COUNT];

static interface* find_interface(const char* ifname) {
	int i;
	for (i = 0; i < MAX_INTERFACE_COUNT; i++) {
		if (interfaces[i].ifname[0] == '\0') {
			memcpy(interfaces[i].ifname, ifname, IFNAMSIZ);
			memset(interfaces[i].hwaddr_org, 0, ETH_ALEN);
			memset(interfaces[i].hwaddr_cur, 0, ETH_ALEN);
			interfaces[i].socket = socket(AF_INET, SOCK_DGRAM, 0);
			return &interfaces[i];
		} else if (strncmp(ifname, interfaces[i].ifname, IFNAMSIZ) == 0) {
			return &interfaces[i];
		}
	}
	return NULL;
}

static int load_hwaddr(const char* ifname, interface* intf) {
	int success = 0;
	char path[PATH_MAX];
	if (snprintf(path, PATH_MAX, MAC_PERSIST_FILENAME, ifname) > 0) {
		int fd = open(path, O_RDONLY);
		if (fd >= 0) {
			if (read(fd, (void*)intf->hwaddr_org, ETH_ALEN) == ETH_ALEN) {
				intf->stored = 1;
				success = 1;
			}
			close(fd);
		}
	}
	return success;
}

static int save_hwaddr(const char* ifname, interface* intf) {
	int success = 0;
	char path[PATH_MAX];
	if (snprintf(path, PATH_MAX, MAC_PERSIST_FILENAME, ifname) > 0) {
		int fd = open(path, O_WRONLY | O_CREAT, 0600);
		if (fd >= 0) {
			if (write(fd, (const void*)intf->hwaddr_org, ETH_ALEN) == ETH_ALEN) {
				intf->stored = 1;
				success = 1;
			}
			close(fd);
		}
	}
	return success;
}

static void sleepms(int ms) {
	struct timespec tim, tim2;
	tim.tv_sec = ms / 1000;
	tim.tv_nsec = (ms % 1000) * 1000000L;
	nanosleep(&tim , &tim2);
}

static int allow_change_wpa_state(interface* intf, struct wpa_supplicant *wpa_s) {
	if (!intf->hwaddr_modified && (wpa_s->wpa_state == WPA_SCANNING)) {
		return 1;
	}
	return 0;
}

static int allow_change_stored_state(interface* intf) {
	return intf->stored;
}

static void randomize_mac(interface* intf, struct wpa_supplicant *wpa_s) {
	if (allow_change_wpa_state(intf, wpa_s) && allow_change_stored_state(intf)) {
		intf->hwaddr_modified = 1; // even on complete failure
		
		if (!randseeded) {
			srand(time(NULL));
			randseeded = 1;
		}
		
		u8 mac[ETH_ALEN];
		memcpy(mac, intf->hwaddr_org, ETH_ALEN);
		
		int i;
		for (i = ETH_ALEN - CONFIG_PRYFI_MAC_CHANGE_DIGITS; i < ETH_ALEN; i++) {
			mac[i] = rand() % 256;
		}
		
		if (linux_set_ifhwaddr(intf->socket, intf->ifname, mac) == 0) {
			sleepms(40);
			
			memcpy(intf->hwaddr_cur, mac, ETH_ALEN);
			memcpy(wpa_s->own_addr, mac, ETH_ALEN);
			
			linux_get_ifhwaddr(intf->socket, intf->ifname, mac);
			
			PRYFI_LOG("pryfi_randomize_mac[%s]: %02x:%02x:%02x:%02x:%02x:%02x", intf->ifname, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		} else {
			PRYFI_LOG("pryfi_randomize_mac[%s]: failed to set MAC", intf->ifname);
		}
	} else {
		PRYFI_LOG("pryfi_randomize_mac[%s]: state does not allow changing MAC", intf->ifname);
	}
}

static void restore_mac(interface* intf, struct wpa_supplicant *wpa_s) {
	intf->hwaddr_modified = 0; // even on complete failure
	
	u8 mac[ETH_ALEN];
	if (linux_get_ifhwaddr(intf->socket, intf->ifname, mac) == 0) {
		if (
			(mac[0] != intf->hwaddr_org[0]) ||
			(mac[1] != intf->hwaddr_org[1]) ||
			(mac[2] != intf->hwaddr_org[2]) ||
			(mac[3] != intf->hwaddr_org[3]) ||
			(mac[4] != intf->hwaddr_org[4]) ||
			(mac[5] != intf->hwaddr_org[5])
		) {
			if (linux_set_ifhwaddr(intf->socket, intf->ifname, intf->hwaddr_org) == 0) {
				sleepms(40);
				
				memcpy(intf->hwaddr_cur, intf->hwaddr_org, ETH_ALEN);
				memcpy(wpa_s->own_addr, intf->hwaddr_org, ETH_ALEN);
				
				PRYFI_LOG("pryfi_restore_mac[%s]: %02x:%02x:%02x:%02x:%02x:%02x", intf->ifname, intf->hwaddr_cur[0], intf->hwaddr_cur[1], intf->hwaddr_cur[2], intf->hwaddr_cur[3], intf->hwaddr_cur[4], intf->hwaddr_cur[5]);
			} else {
				PRYFI_LOG("pryfi_restore_mac[%s]: failed to restore MAC", intf->ifname);
			}
		}
	}
}

void pryfi_store_hwaddr(const char* ifname, u8* addr) {
	interface* intf = find_interface(ifname);
	if (intf == NULL) return;
	
	PRYFI_LOG("pryfi_store_hwaddr[%s]: %02x:%02x:%02x:%02x:%02x:%02x", ifname, addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	if (!intf->stored) {
		if (!load_hwaddr(ifname, intf)) {
			memcpy(intf->hwaddr_org, addr, ETH_ALEN);
			save_hwaddr(ifname, intf);
		}
	}
	memcpy(intf->hwaddr_cur, addr, ETH_ALEN);
}

void pryfi_pre_associate(struct wpa_supplicant *wpa_s, struct wpa_bss *bss, struct wpa_ssid *ssid) {
	interface* intf = find_interface(wpa_s->ifname);
	if (intf == NULL) return;
	
	PRYFI_LOG("pryfi_pre_associate[%s]", wpa_s->ifname);
	restore_mac(intf, wpa_s);
}

void pryfi_pre_trigger_scan(struct wpa_supplicant *wpa_s, struct wpa_driver_scan_params *params) {
	interface* intf = find_interface(wpa_s->ifname);
	if (intf == NULL) return;
	
	PRYFI_LOG("pryfi_pre_trigger_scan[%s]", wpa_s->ifname);
	randomize_mac(intf, wpa_s);
}

void pryfi_notify_scanning(struct wpa_supplicant *wpa_s, int scanning) {
	interface* intf = find_interface(wpa_s->ifname);
	if (intf == NULL) return;
	
	PRYFI_LOG("pryfi_notify_scanning[%s]: %d", wpa_s->ifname, scanning);
	// due to races we're not actually doing anything here, but in _scan_done
}

void pryfi_notify_scan_done(struct wpa_supplicant *wpa_s, int success) {
	interface* intf = find_interface(wpa_s->ifname);
	if (intf == NULL) return;
	
	PRYFI_LOG("pryfi_notify_scan_done[%s]: %d", wpa_s->ifname, success);
	restore_mac(intf, wpa_s);
}

void pryfi_pno_start(struct wpa_supplicant *wpa_s) {
	interface* intf = find_interface(wpa_s->ifname);
	if (intf == NULL) return;
	
	PRYFI_LOG("pryfi_pno_start[%s]", wpa_s->ifname);
	randomize_mac(intf, wpa_s);
}

void pryfi_pno_stop(struct wpa_supplicant *wpa_s) {
	interface* intf = find_interface(wpa_s->ifname);
	if (intf == NULL) return;
	
	PRYFI_LOG("pryfi_pno_stop[%s]", wpa_s->ifname);
	// due to a race we don't restore here, but count on _pre_associate and _scan_done
}