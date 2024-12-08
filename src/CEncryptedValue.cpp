//
// Created by merika on 12/8/2024.
//

#include "../include/CEncryptedValue.hpp"

#include <intrin.h>

VALCRYPT_DISABLE_OPTIMIZATION

template <typename T>
VALCRYPT_FORCEINLINE T valcrypt_xor(const T value, const T key) {
    if (value == key) {
        return value;
    }

    if (sizeof(T) == 1) { // int8_t, uint8_t
        const __m128i mask = _mm_set1_epi8(static_cast<int8_t>(0xFF));
        const __m128i val = _mm_set1_epi8(static_cast<int8_t>(value));
        const __m128i k = _mm_set1_epi8(static_cast<int8_t>(key));
        const __m128i masked_val = _mm_and_si128(val, mask);
        const __m128i masked_key = _mm_and_si128(k, mask);
        const __m128i xor_result = _mm_xor_si128(masked_val, masked_key);
        volatile T result;
        result = static_cast<T>(_mm_extract_epi8(xor_result, 0));
        return result;
    }

    if (sizeof(T) == 2) { // int16_t, uint16_t
        const __m128i mask = _mm_set1_epi16(static_cast<int16_t>(0xFFFF));
        const __m128i val = _mm_set1_epi16(static_cast<int16_t>(value));
        const __m128i k = _mm_set1_epi16(static_cast<int16_t>(key));
        const __m128i masked_val = _mm_and_si128(val, mask);
        const __m128i masked_key = _mm_and_si128(k, mask);
        const __m128i xor_result = _mm_xor_si128(masked_val, masked_key);
        volatile T result;
        result = static_cast<T>(_mm_extract_epi16(xor_result, 0));
        return result;
    }

    if (sizeof(T) == 4) { // int32_t, uint32_t
        const __m128i mask = _mm_set1_epi32(static_cast<int32_t>(0xFFFFFFFF));
        const __m128i val = _mm_set1_epi32(static_cast<int32_t>(value));
        const __m128i k = _mm_set1_epi32(static_cast<int32_t>(key));
        const __m128i masked_val = _mm_and_si128(val, mask);
        const __m128i masked_key = _mm_and_si128(k, mask);
        const __m128i xor_result = _mm_xor_si128(masked_val, masked_key);
        volatile T result;
        result = static_cast<T>(_mm_extract_epi32(xor_result, 0));
        return result;
    }

    if (sizeof(T) == 8) { // int64_t, uint64_t
        const __m128i mask = _mm_set1_epi64x(static_cast<int64_t>(0xFFFFFFFFFFFFFFFF));
        const __m128i val = _mm_set1_epi64x(static_cast<int64_t>(value));
        const __m128i k = _mm_set1_epi64x(static_cast<int64_t>(key));
        const __m128i masked_val = _mm_and_si128(val, mask);
        const __m128i masked_key = _mm_and_si128(k, mask);
        const __m128i xor_result = _mm_xor_si128(masked_val, masked_key);
        volatile T result;
        result = static_cast<T>(_mm_extract_epi64(xor_result, 0));
        return result;
    }

    return T{};
}

namespace valcrypt {

    template<typename T>
    T CEncryptedValue<T>::Cipher(T value) const {
        volatile T result = value;
        result = valcrypt_xor<T>(result, m_Key);
        return result;
    }

    template uint8_t CEncryptedValue<uint8_t>::Cipher(uint8_t) const;
    template uint16_t CEncryptedValue<uint16_t>::Cipher(uint16_t) const;
    template uint32_t CEncryptedValue<uint32_t>::Cipher(uint32_t) const;
    template uint64_t CEncryptedValue<uint64_t>::Cipher(uint64_t) const;
    template int8_t CEncryptedValue<int8_t>::Cipher(int8_t) const;
    template int16_t CEncryptedValue<int16_t>::Cipher(int16_t) const;
    template int32_t CEncryptedValue<int32_t>::Cipher(int32_t) const;
    template int64_t CEncryptedValue<int64_t>::Cipher(int64_t) const;

} // valcrypt

VALCRYPT_ENABLE_OPTIMIZATION
