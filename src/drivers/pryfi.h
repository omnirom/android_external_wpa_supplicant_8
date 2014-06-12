/*
 * WPA Supplicant - Pry-Fi extensions for Android
 * Copyright (c) 2014, Jorrit "Chainfire" Jongma, for The OmniROM Project
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef PRYFI_H
#define PRYFI_H

#include "wpa_supplicant_i.h"

void pryfi_store_hwaddr(const char* ifname, u8* addr);

void pryfi_pre_associate(struct wpa_supplicant *wpa_s, struct wpa_bss *bss, struct wpa_ssid *ssid);

void pryfi_pre_trigger_scan(struct wpa_supplicant *wpa_s, struct wpa_driver_scan_params *params);
void pryfi_notify_scanning(struct wpa_supplicant *wpa_s, int scanning);
void pryfi_notify_scan_done(struct wpa_supplicant *wpa_s, int success);

void pryfi_pno_start(struct wpa_supplicant *wpa_s);
void pryfi_pno_stop(struct wpa_supplicant *wpa_s);

#endif /* PRYFI_H */