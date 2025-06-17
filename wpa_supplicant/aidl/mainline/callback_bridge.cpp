/*
 * WPA Supplicant - Interface to receive callbacks from the core supplicant
 * Copyright (c) 2025, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils.h"
#include "usd_utils.h"

extern "C"
{
#include "callback_bridge.h"
}

using ::aidl::android::system::wifi::mainline_supplicant::UsdMessageInfo;

void mainline_aidl_notify_usd_service_discovered(struct wpa_supplicant *wpa_s,
        enum nan_service_protocol_type srv_proto_type,
        int subscribe_id, int peer_publish_id, const u8 *peer_addr,
        bool fsd, const u8 *ssi, size_t ssi_len) {
    if (!wpa_s || !peer_addr)
        return;

    auto callback = getStaIfaceCallback(wpa_s->ifname);
    if (!callback)
        return;

    wpa_printf(MSG_DEBUG, "Notifying USD service discovered");
    auto serviceDiscoveryInfo = createUsdServiceDiscoveryInfo(
        srv_proto_type, subscribe_id, peer_publish_id, peer_addr, fsd, ssi, ssi_len);
    callback->onUsdServiceDiscovered(serviceDiscoveryInfo);
}

void mainline_aidl_notify_usd_publish_replied(struct wpa_supplicant *wpa_s,
        enum nan_service_protocol_type srv_proto_type,
        int publish_id, int peer_subscribe_id,
        const u8 *peer_addr, const u8 *ssi, size_t ssi_len) {
    if (!wpa_s || !peer_addr)
        return;

    auto callback = getStaIfaceCallback(wpa_s->ifname);
    if (!callback)
        return;

    wpa_printf(MSG_DEBUG, "Notifying USD publish replied");
    auto serviceDiscoveryInfo = createUsdServiceDiscoveryInfo(
        srv_proto_type, publish_id, peer_subscribe_id, peer_addr, false /* fsd */,
        ssi, ssi_len);
    callback->onUsdPublishReplied(serviceDiscoveryInfo);
}

void mainline_aidl_notify_usd_message_received(struct wpa_supplicant *wpa_s, int id,
        int peer_instance_id, const u8 *peer_addr,
        const u8 *message, size_t message_len) {
    if (!wpa_s || !peer_addr)
        return;

    auto callback = getStaIfaceCallback(wpa_s->ifname);
    if (!callback)
        return;

    UsdMessageInfo messageInfo;
    messageInfo.ownId = id;
    messageInfo.peerId = peer_instance_id;
    messageInfo.peerMacAddress = macAddrBytesToArray(peer_addr);
    messageInfo.message = message ? byteArrToVec(message, message_len) : std::vector<uint8_t>();

    wpa_printf(MSG_DEBUG, "Notifying USD message received");
    callback->onUsdMessageReceived(messageInfo);
}

void mainline_aidl_notify_usd_publish_terminated(struct wpa_supplicant *wpa_s,
        int publish_id, enum nan_de_reason reason) {
    if (!wpa_s)
        return;

    auto callback = getStaIfaceCallback(wpa_s->ifname);
    if (!callback)
        return;

    wpa_printf(MSG_DEBUG, "Notifying USD publish terminated");
    callback->onUsdPublishTerminated(
        publish_id, convertInternalUsdTerminateReasonCodeToAidl(reason));
}

void mainline_aidl_notify_usd_subscribe_terminated(struct wpa_supplicant *wpa_s,
        int subscribe_id, enum nan_de_reason reason) {
    if (!wpa_s)
        return;

    auto callback = getStaIfaceCallback(wpa_s->ifname);
    if (!callback)
        return;

    wpa_printf(MSG_DEBUG, "Notifying USD subscribe terminated");
    callback->onUsdSubscribeTerminated(
        subscribe_id, convertInternalUsdTerminateReasonCodeToAidl(reason));
}
