/*
 * WPA Supplicant - Interface to receive callbacks from the core supplicant
 * Copyright (c) 2025, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MAINLINE_SUPPLICANT_CALLBACK_BRIDGE_H
#define MAINLINE_SUPPLICANT_CALLBACK_BRIDGE_H

/**
 * Intermediary layer to receive callbacks from the core supplicant.
 *
 * For each callback, we provide a full implementation if the MAINLINE_SUPPLICANT
 * flag is enabled. Otherwise, we provide an empty default implementation for builds
 * that do not have the flag enabled (ex. the vendor supplicant).
 */
#ifdef _cplusplus
extern "C"
{
#endif  // _cplusplus

#include "utils/common.h"
#include "src/common/nan_de.h"
#include "wpa_supplicant_i.h"

#ifdef MAINLINE_SUPPLICANT

void mainline_aidl_notify_usd_service_discovered(struct wpa_supplicant *wpa_s,
    enum nan_service_protocol_type srv_proto_type,
    int subscribe_id, int peer_publish_id, const u8 *peer_addr,
    bool fsd, const u8 *ssi, size_t ssi_len);
void mainline_aidl_notify_usd_publish_replied(struct wpa_supplicant *wpa_s,
    enum nan_service_protocol_type srv_proto_type,
    int publish_id, int peer_subscribe_id,
    const u8 *peer_addr, const u8 *ssi, size_t ssi_len);
void mainline_aidl_notify_usd_message_received(struct wpa_supplicant *wpa_s, int id,
    int peer_instance_id, const u8 *peer_addr,
    const u8 *message, size_t message_len);
void mainline_aidl_notify_usd_publish_terminated(struct wpa_supplicant *wpa_s,
    int publish_id, enum nan_de_reason reason);
void mainline_aidl_notify_usd_subscribe_terminated(struct wpa_supplicant *wpa_s,
    int subscribe_id, enum nan_de_reason reason);

#else // MAINLINE_SUPPLICANT

static void mainline_aidl_notify_usd_service_discovered(struct wpa_supplicant *wpa_s,
    enum nan_service_protocol_type srv_proto_type,
    int subscribe_id, int peer_publish_id, const u8 *peer_addr,
    bool fsd, const u8 *ssi, size_t ssi_len) {}
static void mainline_aidl_notify_usd_publish_replied(struct wpa_supplicant *wpa_s,
    enum nan_service_protocol_type srv_proto_type,
    int publish_id, int peer_subscribe_id,
    const u8 *peer_addr, const u8 *ssi, size_t ssi_len) {}
static void mainline_aidl_notify_usd_message_received(struct wpa_supplicant *wpa_s, int id,
    int peer_instance_id, const u8 *peer_addr,
    const u8 *message, size_t message_len) {}
static void mainline_aidl_notify_usd_publish_terminated(struct wpa_supplicant *wpa_s,
    int publish_id, enum nan_de_reason reason) {}
static void mainline_aidl_notify_usd_subscribe_terminated(struct wpa_supplicant *wpa_s,
    int subscribe_id, enum nan_de_reason reason) {}

#endif // MAINLINE_SUPPLICANT

#ifdef _cplusplus
}
#endif  // _cplusplus

#endif // MAINLINE_SUPPLICANT_CALLBACK_BRIDGE_H
