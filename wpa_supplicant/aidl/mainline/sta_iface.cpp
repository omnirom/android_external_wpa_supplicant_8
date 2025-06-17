/*
 * WPA Supplicant - Station mode interface
 * Copyright (c) 2024, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "callback_manager.h"
#include "sta_iface.h"
#include "usd_utils.h"

extern "C"
{
#include "utils/common.h"
#include "nan_usd.h"
#include "wpa_supplicant_i.h"
}

StaIface::StaIface(struct wpa_global* wpa_global, std::string iface_name)
    : wpa_global_(wpa_global), iface_name_(iface_name) {}

struct wpa_supplicant* StaIface::retrieveIfacePtr() {
    return wpa_supplicant_get_iface(wpa_global_, iface_name_.c_str());
}

::ndk::ScopedAStatus StaIface::registerCallback(
        const std::shared_ptr<IStaInterfaceCallback>& callback) {
    CallbackManager* callbackManager = CallbackManager::getInstance();
    WPA_ASSERT(callbackManager);
    if (callbackManager->registerStaIfaceCallback(iface_name_, callback)) {
        return ndk::ScopedAStatus::ok();
    } else {
        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
    }
}

::ndk::ScopedAStatus StaIface::getUsdCapabilities(UsdCapabilities* _aidl_return) {
    UsdCapabilities capabilities;
    capabilities.isUsdPublisherSupported = kIsUsdPublisherSupported;
    capabilities.isUsdSubscriberSupported = kIsUsdSubscriberSupported;
    capabilities.maxLocalSsiLengthBytes = kMaxUsdLocalSsiLengthBytes;
    capabilities.maxServiceNameLengthBytes = kMaxUsdServiceNameLengthBytes;
    capabilities.maxMatchFilterLengthBytes = kMaxUsdMatchFilterLengthBytes;
    capabilities.maxNumPublishSessions = kMaxNumUsdPublishSessions;
    capabilities.maxNumSubscribeSessions = kMaxNumUsdSubscribeSessions;
    *_aidl_return = capabilities;
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus StaIface::startUsdPublish(int32_t cmdId,
        const UsdPublishConfig& publishConfig) {
    if (!validateUsdPublishConfig(publishConfig)) {
        wpa_printf(MSG_ERROR, "USD publish config is invalid");
        return createStatus(SupplicantStatusCode::FAILURE_ARGS_INVALID);
    }
    wpabuf_unique_ptr ssiBuffer = {nullptr, nullptr};
    if (!publishConfig.baseConfig.serviceSpecificInfo.empty()) {
        ssiBuffer = convertVectorToWpaBuf(publishConfig.baseConfig.serviceSpecificInfo);
        if (ssiBuffer.get() == nullptr) {
            wpa_printf(MSG_ERROR, "Unable to convert USD publish SSI to buffer");
            return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
        }
    }

    struct wpa_supplicant *wpa_s = retrieveIfacePtr();
    struct nan_publish_params nanPublishParams =
        convertAidlUsdPublishConfigToInternal(publishConfig);
    int publishId = wpas_nan_usd_publish(
        wpa_s, publishConfig.baseConfig.serviceName.c_str(),
        convertAidlServiceProtoTypeToInternal(
            publishConfig.baseConfig.serviceProtoType),
        ssiBuffer.get(), &nanPublishParams, false /* p2p */);

    // Core supplicant does not have an internal callback for USD publish,
    // so invoke the failure callback directly if needed.
    if (publishId < 0) {
        wpa_printf(MSG_INFO, "Failed to configure USD publish");
        auto callback = getStaIfaceCallback(iface_name_);
        if (callback) {
            callback->onUsdPublishConfigFailed(
                cmdId, IStaInterfaceCallback::UsdConfigErrorCode::FAILURE_UNKNOWN);
        }
        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus StaIface::startUsdSubscribe(int32_t cmdId,
        const UsdSubscribeConfig& subscribeConfig) {
    if (!validateUsdSubscribeConfig(subscribeConfig)) {
        wpa_printf(MSG_ERROR, "USD subscribe config is invalid");
        return createStatus(SupplicantStatusCode::FAILURE_ARGS_INVALID);
    }
    wpabuf_unique_ptr ssiBuffer = {nullptr, nullptr};
    if (!subscribeConfig.baseConfig.serviceSpecificInfo.empty()) {
        ssiBuffer = convertVectorToWpaBuf(subscribeConfig.baseConfig.serviceSpecificInfo);
        if (ssiBuffer.get() == nullptr) {
            wpa_printf(MSG_ERROR, "Unable to convert USD subscribe SSI to buffer");
            return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
        }
    }

    struct wpa_supplicant *wpa_s = retrieveIfacePtr();
    struct nan_subscribe_params nanSubscribeParams =
        convertAidlUsdSubscribeConfigToInternal(subscribeConfig);
    int subscribeId = wpas_nan_usd_subscribe(
        wpa_s, subscribeConfig.baseConfig.serviceName.c_str(),
        convertAidlServiceProtoTypeToInternal(
            subscribeConfig.baseConfig.serviceProtoType),
        ssiBuffer.get(), &nanSubscribeParams, false /* p2p */);

    // Core supplicant does not have an internal callback for USD subscribe,
    // so invoke the failure callback directly if needed.
    if (subscribeId < 0) {
        wpa_printf(MSG_INFO, "Failed to configure USD subscribe");
        auto callback = getStaIfaceCallback(iface_name_);
        if (callback) {
            callback->onUsdSubscribeConfigFailed(
                cmdId, IStaInterfaceCallback::UsdConfigErrorCode::FAILURE_UNKNOWN);
        }
        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus StaIface::updateUsdPublish(int32_t publishId,
        const std::vector<uint8_t>& serviceSpecificInfo) {
    if (!checkContainerSize(serviceSpecificInfo, kMaxUsdLocalSsiLengthBytes)) {
        wpa_printf(MSG_ERROR, "Updated USD publish SSI of size %zu exceeds the"
            " supported size of %d", serviceSpecificInfo.size(),
            kMaxUsdLocalSsiLengthBytes);
        return createStatus(SupplicantStatusCode::FAILURE_ARGS_INVALID);
    }
    wpabuf_unique_ptr ssiBuffer = {nullptr, nullptr};
    if (!serviceSpecificInfo.empty()) {
        ssiBuffer = convertVectorToWpaBuf(serviceSpecificInfo);
        if (ssiBuffer.get() == nullptr) {
            wpa_printf(MSG_ERROR, "Unable to convert updated USD publish SSI to buffer");
            return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
        }
    }
    int status = wpas_nan_usd_update_publish(
        retrieveIfacePtr(), publishId, ssiBuffer.get());
    if (status < 0) {
        wpa_printf(MSG_ERROR, "Failed to update USD publish");
        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus StaIface::cancelUsdPublish(int32_t publishId) {
    // Status code is returned by the callback
    wpas_nan_usd_cancel_publish(retrieveIfacePtr(), publishId);
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus StaIface::cancelUsdSubscribe(int32_t subscribeId) {
    // Status code is returned by the callback
    wpas_nan_usd_cancel_subscribe(retrieveIfacePtr(), subscribeId);
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus StaIface::sendUsdMessage(const UsdMessageInfo& messageInfo) {
    if (!checkContainerSize(messageInfo.message, kMaxUsdLocalSsiLengthBytes)) {
        wpa_printf(MSG_ERROR, "USD message of size %zu exceeds the supported size of %d",
            messageInfo.message.size(), kMaxUsdLocalSsiLengthBytes);
        return createStatus(SupplicantStatusCode::FAILURE_ARGS_INVALID);
    }
    wpabuf_unique_ptr msgBuffer = {nullptr, nullptr};
    if (!messageInfo.message.empty()) {
        msgBuffer = convertVectorToWpaBuf(messageInfo.message);
        if (msgBuffer.get() == nullptr) {
            wpa_printf(MSG_ERROR, "Unable to convert USD message contents to buffer");
            return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
        }
    }
    int handle = messageInfo.ownId;
    int reqInstanceId = messageInfo.peerId;
    int status = wpas_nan_usd_transmit(
        retrieveIfacePtr(), handle, msgBuffer.get(), nullptr /* elems */,
        messageInfo.peerMacAddress.data(), reqInstanceId);
    if (status < 0) {
        wpa_printf(MSG_ERROR, "Failed to send USD message");
        return createStatus(SupplicantStatusCode::FAILURE_UNKNOWN);
    }
    return ndk::ScopedAStatus::ok();
}
