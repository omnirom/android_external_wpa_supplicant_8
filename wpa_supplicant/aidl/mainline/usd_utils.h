/*
 * WPA Supplicant - Helper functions for USD
 * Copyright (c) 2025, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MAINLINE_SUPPLICANT_USD_UTILS_H
#define MAINLINE_SUPPLICANT_USD_UTILS_H

#include "utils.h"

#include <aidl/android/system/wifi/mainline_supplicant/IStaInterface.h>
#include <aidl/android/system/wifi/mainline_supplicant/UsdServiceProtoType.h>

extern "C"
{
#include "utils/common.h"
#include "src/common/nan_de.h"
}

using ::aidl::android::system::wifi::mainline_supplicant::IStaInterface;
using ::aidl::android::system::wifi::mainline_supplicant::UsdServiceProtoType;

constexpr bool kIsUsdPublisherSupported = true;
constexpr bool kIsUsdSubscriberSupported = true;
constexpr int32_t kMaxUsdLocalSsiLengthBytes = 1400;
constexpr int32_t kMaxUsdServiceNameLengthBytes = 255;
constexpr int32_t kMaxUsdMatchFilterLengthBytes = 0;
constexpr int32_t kMaxNumUsdPublishSessions = NAN_DE_MAX_SERVICE;
constexpr int32_t kMaxNumUsdSubscribeSessions = NAN_DE_MAX_SERVICE;

static bool validateUsdBaseConfig(IStaInterface::UsdBaseConfig baseConfig) {
    if (!isValidEnumValue(baseConfig.serviceProtoType,
            UsdServiceProtoType::GENERIC, UsdServiceProtoType::CSA_MATTER)) {
        wpa_printf(MSG_ERROR, "Unknown protocol type received: %d",
            static_cast<int>(baseConfig.serviceProtoType));
        return false;
    }
    if (!checkContainerSize(baseConfig.serviceName, kMaxUsdServiceNameLengthBytes)) {
        wpa_printf(MSG_ERROR, "Service name of size %zu exceeds the supported size of %d",
            baseConfig.serviceName.size(), kMaxUsdServiceNameLengthBytes);
        return false;
    }
    if (!checkContainerSize(baseConfig.serviceSpecificInfo, kMaxUsdLocalSsiLengthBytes)) {
        wpa_printf(MSG_ERROR, "Service specific info of size %zu exceeds"
            " the supported size of %d", baseConfig.serviceSpecificInfo.size(),
            kMaxUsdLocalSsiLengthBytes);
        return false;
    }
    if (baseConfig.txMatchFilter.has_value() && !checkContainerSize(
            baseConfig.txMatchFilter.value(), kMaxUsdMatchFilterLengthBytes)) {
        wpa_printf(MSG_ERROR, "TX match filter of size %zu exceeds"
            " the supported size of %d", baseConfig.txMatchFilter.value().size(),
            kMaxUsdMatchFilterLengthBytes);
        return false;
    }
    if (baseConfig.rxMatchFilter.has_value() && !checkContainerSize(
            baseConfig.rxMatchFilter.value(), kMaxUsdMatchFilterLengthBytes)) {
        wpa_printf(MSG_ERROR, "RX match filter of size %zu exceeds"
            " the supported size of %d", baseConfig.rxMatchFilter.value().size(),
            kMaxUsdMatchFilterLengthBytes);
        return false;
    }
    return true;
}

static bool validateUsdPublishConfig(IStaInterface::UsdPublishConfig publishConfig) {
    if (!validateUsdBaseConfig(publishConfig.baseConfig)) {
        return false;
    }
    if (!isValidEnumValue(publishConfig.publishType,
            IStaInterface::UsdPublishType::SOLICITED_ONLY,
            IStaInterface::UsdPublishType::SOLICITED_AND_UNSOLICITED)) {
        wpa_printf(MSG_ERROR, "Unknown publish type received: %d",
            static_cast<int>(publishConfig.publishType));
        return false;
    }
    if (!isValidEnumValue(publishConfig.transmissionType,
            IStaInterface::UsdPublishTransmissionType::UNICAST,
            IStaInterface::UsdPublishTransmissionType::MULTICAST)) {
        wpa_printf(MSG_ERROR, "Unknown transmission type received: %d",
            static_cast<int>(publishConfig.transmissionType));
        return false;
    }
    return true;
}

static bool validateUsdSubscribeConfig(IStaInterface::UsdSubscribeConfig subscribeConfig) {
    if (!validateUsdBaseConfig(subscribeConfig.baseConfig)) {
        return false;
    }
    if (!isValidEnumValue(subscribeConfig.subscribeType,
            IStaInterface::UsdSubscribeType::PASSIVE_MODE,
            IStaInterface::UsdSubscribeType::ACTIVE_MODE)) {
        wpa_printf(MSG_ERROR, "Unknown subscribe type received: %d",
            static_cast<int>(subscribeConfig.subscribeType));
        return false;
    }
    return true;
}

static struct nan_publish_params convertAidlUsdPublishConfigToInternal(
        IStaInterface::UsdPublishConfig publishConfig) {
    struct nan_publish_params nanPublishParams;
    nanPublishParams.unsolicited =
        publishConfig.publishType == IStaInterface::UsdPublishType::SOLICITED_AND_UNSOLICITED
            || publishConfig.publishType == IStaInterface::UsdPublishType::UNSOLICITED_ONLY;
    nanPublishParams.solicited =
        publishConfig.publishType == IStaInterface::UsdPublishType::SOLICITED_AND_UNSOLICITED
            || publishConfig.publishType == IStaInterface::UsdPublishType::SOLICITED_ONLY;
    nanPublishParams.solicited_multicast = nanPublishParams.solicited &&
        publishConfig.transmissionType == IStaInterface::UsdPublishTransmissionType::MULTICAST;
    nanPublishParams.ttl = publishConfig.baseConfig.ttlSec;
    nanPublishParams.fsd = publishConfig.isFsd;
    nanPublishParams.freq = publishConfig.baseConfig.defaultFreqMhz;
    nanPublishParams.announcement_period = publishConfig.announcementPeriodMillis;
    nanPublishParams.disable_events = !publishConfig.eventsEnabled;
    // Pass the original pointer to the freq list, since the receiver will memcpy the data
    nanPublishParams.freq_list = publishConfig.baseConfig.freqsMhz.empty()
        ? NULL : publishConfig.baseConfig.freqsMhz.data();
    return nanPublishParams;
}

static struct nan_subscribe_params convertAidlUsdSubscribeConfigToInternal(
        IStaInterface::UsdSubscribeConfig subscribeConfig) {
    struct nan_subscribe_params nanSubscribeParams;
    nanSubscribeParams.active =
        subscribeConfig.subscribeType == IStaInterface::UsdSubscribeType::ACTIVE_MODE;
    nanSubscribeParams.ttl = subscribeConfig.baseConfig.ttlSec;
    nanSubscribeParams.freq = subscribeConfig.baseConfig.defaultFreqMhz;
    nanSubscribeParams.query_period = subscribeConfig.queryPeriodMillis;
    // Pass the original pointer to the freq list, since the receiver will memcpy the data
    nanSubscribeParams.freq_list = subscribeConfig.baseConfig.freqsMhz.empty()
        ? NULL : subscribeConfig.baseConfig.freqsMhz.data();
    return nanSubscribeParams;
}

static nan_service_protocol_type convertAidlServiceProtoTypeToInternal(
        UsdServiceProtoType serviceProtoType) {
    switch (serviceProtoType) {
        case UsdServiceProtoType::GENERIC:
            return NAN_SRV_PROTO_GENERIC;
        case UsdServiceProtoType::CSA_MATTER:
            return NAN_SRV_PROTO_CSA_MATTER;
        default:
            // Default case is not expected, due to the USD validation method
            return NAN_SRV_PROTO_GENERIC;
    };
}

static UsdServiceProtoType convertInternalUsdServiceProtoTypeToAidl(
        nan_service_protocol_type protocolType) {
    switch (protocolType) {
        case NAN_SRV_PROTO_GENERIC:
            return UsdServiceProtoType::GENERIC;
        case NAN_SRV_PROTO_CSA_MATTER:
            return UsdServiceProtoType::CSA_MATTER;
        default:
            wpa_printf(MSG_ERROR, "Received invalid USD proto type %d from internal",
                static_cast<int>(protocolType));
            return UsdServiceProtoType::GENERIC;
    }
}

static IStaInterfaceCallback::UsdServiceDiscoveryInfo createUsdServiceDiscoveryInfo(
        enum nan_service_protocol_type srv_proto_type,
        int own_id, int peer_id, const u8 *peer_addr,
        bool fsd, const u8 *ssi, size_t ssi_len) {
    IStaInterfaceCallback::UsdServiceDiscoveryInfo discoveryInfo;
    discoveryInfo.ownId = own_id;
    discoveryInfo.peerId = peer_id;
    // TODO: Fill the matchFilter field in the AIDL struct
    discoveryInfo.matchFilter = std::vector<uint8_t>();
    discoveryInfo.peerMacAddress = macAddrBytesToArray(peer_addr);
    discoveryInfo.serviceProtoType = convertInternalUsdServiceProtoTypeToAidl(srv_proto_type);
    discoveryInfo.serviceSpecificInfo = ssi ? byteArrToVec(ssi, ssi_len) : std::vector<uint8_t>();
    discoveryInfo.isFsd = fsd;
    return discoveryInfo;
}

static IStaInterfaceCallback::UsdTerminateReasonCode convertInternalUsdTerminateReasonCodeToAidl(
        nan_de_reason terminateReason) {
    switch (terminateReason) {
        case NAN_DE_REASON_TIMEOUT:
            return IStaInterfaceCallback::UsdTerminateReasonCode::TIMEOUT;
        case NAN_DE_REASON_USER_REQUEST:
            return IStaInterfaceCallback::UsdTerminateReasonCode::USER_REQUESTED;
        case NAN_DE_REASON_FAILURE:
        default:
            return IStaInterfaceCallback::UsdTerminateReasonCode::FAILURE_UNKNOWN;
    }
}

#endif // MAINLINE_SUPPLICANT_USD_UTILS_H
