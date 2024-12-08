//
// Created by merika on 12/8/2024.
//

#ifndef CENCRYPTEDVALUE_HPP
#define CENCRYPTEDVALUE_HPP

#ifndef VALCRYPT_NOINLINE
    #ifdef _MSC_VER
        #define VALCRYPT_FORCEINLINE __forceinline
    #else
        #define VALCRYPT_FORCEINLINE inline __attribute__((always_inline))
    #endif
#else
        #define VALCRYPT_FORCEINLINE
#endif

#ifdef _MSC_VER
    #define VALCRYPT_DISABLE_OPTIMIZATION __pragma(optimize("", off))
    #define VALCRYPT_ENABLE_OPTIMIZATION __pragma(optimize("", on))
#else
    #define VALCRYPT_DISABLE_OPTIMIZATION _Pragma("optimize(\"O0\")")
    #define VALCRYPT_ENABLE_OPTIMIZATION _Pragma("optimize(\"O2\")")
#endif

VALCRYPT_DISABLE_OPTIMIZATION

#include <random>
#include <cstdint>
#include <type_traits>

namespace valcrypt {

    template <typename T>
    class CEncryptedValue {
        static_assert(std::is_integral<T>::value, "T must be an integral type");

    public:
        VALCRYPT_FORCEINLINE CEncryptedValue() : m_Key(GetRandomSeed()), m_EncryptedValue(Cipher(T{})) {
        }

        VALCRYPT_FORCEINLINE explicit CEncryptedValue(T value)
            : m_Key(GetRandomSeed()), m_EncryptedValue(Cipher(value))  {
        }

        CEncryptedValue& operator=(T value) {
            m_EncryptedValue = Cipher(value);
            return *this;
        }

        VALCRYPT_FORCEINLINE T GetDecrypted() const {
            return Cipher(m_EncryptedValue);
        }

        VALCRYPT_FORCEINLINE T GetEncrypted() const {
            return m_EncryptedValue;
        }

        CEncryptedValue operator+(const CEncryptedValue& other) const {
            return CEncryptedValue(GetDecrypted() + other.GetDecrypted());
        }

        CEncryptedValue operator-(const CEncryptedValue& other) const {
            return CEncryptedValue(GetDecrypted() - other.GetDecrypted());
        }

        CEncryptedValue operator+(const T other) const {
            return CEncryptedValue(GetDecrypted() + other);
        }

        CEncryptedValue operator-(const T other) const {
            return CEncryptedValue(GetDecrypted() - other);
        }

        bool operator==(const CEncryptedValue& other) const {
            return GetEncrypted() == other.GetEncrypted();
        }

        bool operator!=(const CEncryptedValue& other) const {
            return !(*this == other);
        }

    private:
        #ifdef _MSC_VER
            VALCRYPT_FORCEINLINE T Cipher(T value) const;
        #else
            T Cipher(T value) const;
        #endif

        VALCRYPT_FORCEINLINE static uint64_t GetRandomSeed() {
            std::random_device rd;
            std::mt19937 engine(rd());
            std::uniform_int_distribution<uint64_t> dist(0, std::numeric_limits<uint64_t>::max());
            return dist(engine);
        }

    private:
        uint64_t m_Key = 0;
        uint64_t m_EncryptedValue = 0;
    };

} // valcrypt

VALCRYPT_ENABLE_OPTIMIZATION

#endif //CENCRYPTEDVALUE_HPP
