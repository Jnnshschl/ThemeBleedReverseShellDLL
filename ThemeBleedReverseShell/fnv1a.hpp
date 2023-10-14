#pragma once

#define CX_Fnv1a(s) FNV1A::FnvHash<s>::v
#define CX_IFnv1a(s) FNV1A::IFnvHash<s>::v

namespace FNV1A
{
    typedef unsigned long long fnvhash;
    constexpr fnvhash FnvValue = 14695981039346656037ull;
    constexpr fnvhash FnvPrime = 1099511628211ull;

    // CASE-SENSITIVE
    template<typename T>
    __forceinline constexpr fnvhash Hash(T c) noexcept
    {
        fnvhash v = FnvValue;
        for (; *c; ++c) v = (v ^ static_cast<fnvhash>(*c)) * FnvPrime;
        return v;
    }

    template<typename T>
    __forceinline constexpr fnvhash HashFixed(T c, size_t s) noexcept
    {
        fnvhash v = FnvValue;
        for (size_t i = 0; i < s; ++i) v = (v ^ static_cast<fnvhash>(c[i])) * FnvPrime;
        return v;
    }

    template <typename CharT, size_t N>
    struct FnvString
    {
        fnvhash v;
        constexpr FnvString(const CharT(&foo)[N + 1]) noexcept
            : v(Hash(foo))
        {}
    };

    template <typename CharT, size_t N>
    FnvString(const CharT(&str)[N]) -> FnvString<CharT, N - 1>;

    template <FnvString s>
    struct FnvHash { enum : fnvhash { v = s.v }; };

    // CASE-INSENSITIVE
    template<typename CharT>
    __forceinline constexpr auto ToLower(CharT c) noexcept
    {
        return (c >= 65 && c <= 90) ? static_cast<CharT>(c + 32) : c;
    }

    template<typename T>
    __forceinline constexpr fnvhash IHash(T c) noexcept
    {
        fnvhash v = FnvValue;
        for (; *c; ++c) v = (v ^ static_cast<fnvhash>(ToLower(*c))) * FnvPrime;
        return v;
    }

    template<typename T>
    __forceinline constexpr fnvhash IHashFixed(T c, size_t s) noexcept
    {
        fnvhash v = FnvValue;
        for (size_t i = 0; i < s; ++i) v = (v ^ static_cast<fnvhash>(ToLower(c[i]))) * FnvPrime;
        return v;
    }

    template <typename CharT, size_t N>
    struct IFnvString
    {
        fnvhash v;
        constexpr IFnvString(const CharT(&foo)[N + 1]) noexcept
            : v(IHash(foo))
        {}
    };

    template <typename CharT, size_t N>
    IFnvString(const CharT(&str)[N]) -> IFnvString<CharT, N - 1>;

    template <IFnvString s>
    struct IFnvHash { enum : fnvhash { v = s.v }; };
}