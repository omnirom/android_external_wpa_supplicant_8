/*
 * WPA Supplicant - Utilities for the mainline supplicant
 * Copyright (c) 2024, Google Inc. All rights reserved.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MAINLINE_SUPPLICANT_UTILS_H
#define MAINLINE_SUPPLICANT_UTILS_H

#include "callback_manager.h"

#include <aidl/android/system/wifi/mainline_supplicant/SupplicantStatusCode.h>

extern "C"
{
#include "utils/common.h"
#include "wpabuf.h"
}

namespace {
// Custom deleter for wpabuf
void freeWpaBuf(wpabuf *ptr) { wpabuf_free(ptr); }
}

using ::aidl::android::system::wifi::mainline_supplicant::SupplicantStatusCode;

using wpabuf_unique_ptr = std::unique_ptr<wpabuf, void (*)(wpabuf *)>;

inline ndk::ScopedAStatus createStatus(SupplicantStatusCode statusCode) {
    return ndk::ScopedAStatus::fromServiceSpecificError(
        static_cast<int32_t>(statusCode));
}

inline ndk::ScopedAStatus createStatusWithMsg(
        SupplicantStatusCode statusCode, std::string msg) {
    return ndk::ScopedAStatus::fromServiceSpecificErrorWithMessage(
        static_cast<int32_t>(statusCode), msg.c_str());
}

// Check whether the container is within the maximum size
template <typename T>
inline bool checkContainerSize(const T& container, int maxSize) {
    return container.size() <= maxSize;
}

// Check whether the enum value is within the specified range
template <typename T>
inline bool isValidEnumValue(T value, T enumRangeMin, T enumRangeMax) {
    return static_cast<uint32_t>(value) >= static_cast<uint32_t>(enumRangeMin)
        && static_cast<uint32_t>(value) <= static_cast<uint32_t>(enumRangeMax);
}

// Create a unique_ptr for a wpabuf ptr with a custom deleter
inline wpabuf_unique_ptr createWpaBufUniquePtr(struct wpabuf *raw_ptr) {
    return {raw_ptr, freeWpaBuf};
}

// Create a wpabuf ptr with a custom deleter, copying the data from the provided vector
inline wpabuf_unique_ptr convertVectorToWpaBuf(const std::vector<uint8_t> &data) {
    return createWpaBufUniquePtr(wpabuf_alloc_copy(data.data(), data.size()));
}

// Convert a byte array representation of a MAC address to an std::array
inline std::array<uint8_t, ETH_ALEN> macAddrBytesToArray(const uint8_t* mac_addr) {
    std::array<uint8_t, ETH_ALEN> arr;
    std::copy(mac_addr, mac_addr + ETH_ALEN, std::begin(arr));
    return arr;
}

// Convert a byte array to an std::vector
inline std::vector<uint8_t> byteArrToVec(const uint8_t* arr, int len) {
    return std::vector<uint8_t>{arr, arr + len};
}

// Wrapper to retrieve a STA iface callback registered with the callback manager
static std::shared_ptr<IStaInterfaceCallback> getStaIfaceCallback(
        std::string ifaceName) {
    CallbackManager* callback_manager = CallbackManager::getInstance();
    if (!callback_manager) {
        return nullptr;
    }
    return callback_manager->getStaIfaceCallback(ifaceName);
}

#endif // MAINLINE_SUPPLICANT_UTILS_H
