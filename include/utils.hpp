#ifndef __UTILS__H__
#define __UTILS__H__

#include <algorithm>
#include <cassert>
#include <ctime>
#include <iostream>
#include <iterator>
#include <list>
#include <map>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <sys/time.h>

namespace minio_ns3 {

namespace utils {

/**
 * URL encodes string.
 *
 * This  function  will  convert  the given input string to an URL encoded
 * string and return that as a new allocated string. All input  characters
 * that  are  not a-z, A-Z or 0-9 will be converted to their "URL escaped"
 * version (%NN where NN is a two-digit hexadecimal number).
 */
std::string UrlEncode(const std::string& str);

/**
 * Decodes URL encoded string.
 *
 * This  function  will  convert  the  given  URL encoded input string to a
 * "plain string" and return that as a new allocated string. All input
 * characters that are URL encoded (%XX) where XX is a two-digit
 * hexadecimal number, or +) will be converted to their plain text versions
 * (up to a ? letter, no + letters to the right of a ? letter will be
 * converted).
 */
std::string UrlDecode(const std::string& str);

// FormatTime formats time as per format.
std::string FormatTime(const std::tm* time, const char* format);

// ToLower converts string to lower case.
std::string ToLower(std::string str);

// Join returns a string of joined values by delimiter.
std::string Join(std::list<std::string> values, std::string delimiter);

// Join returns a string of joined values by delimiter.
std::string Join(std::vector<std::string> values, std::string delimiter);

// Sha256hash computes SHA-256 of data and return hash as hex encoded value.
std::string Sha256Hash(std::string_view str);

// Base64Encode encodes string to base64.
std::string Base64Encode(std::string_view str);

/**
 * Time represents date and time with timezone.
 */
class Time {
private:
    struct timeval tv_ = {0, 0};
    bool utc_ = false;

public:
    Time() {}

    Time(std::time_t tv_sec, suseconds_t tv_usec, bool utc) {
        this->tv_.tv_sec = tv_sec;
        this->tv_.tv_usec = tv_usec;
        this->utc_ = utc;
    }

    void Add(time_t seconds) { tv_.tv_sec += seconds; }

    std::tm* ToUTC();

    std::string ToSignerDate();

    std::string ToAmzDate();

    std::string ToHttpHeaderValue();

    static Time FromHttpHeaderValue(const char* value);

    std::string ToISO8601UTC();

    static Time FromISO8601UTC(const char* value);

    static Time Now() {
        Time t;
        gettimeofday(&t.tv_, NULL);
        return t;
    }

    operator bool() const { return tv_.tv_sec != 0 && tv_.tv_usec != 0; }
}; // class Time

/**
 * Multimap represents dictionary of keys and their multiple values.
 */
class Multimap {
private:
    std::map<std::string, std::set<std::string>> map_;
    std::map<std::string, std::set<std::string>> keys_;

public:
    Multimap() {}

    Multimap(const Multimap& headers) { this->AddAll(headers); }

    void Add(std::string key, std::string value);

    void AddAll(const Multimap& headers);

    std::list<std::string> ToHttpHeaders();

    std::string ToQueryString();

    operator bool() const { return !map_.empty(); }

    bool Contains(std::string_view key);

    std::list<std::string> Get(std::string_view key);

    std::string GetFront(std::string_view key);

    std::list<std::string> Keys();

    void GetCanonicalHeaders(std::string& signed_headers,
                             std::string& canonical_headers);

    std::string GetCanonicalQueryString();
}; // class Multimap

} // namespace utils

} // namespace minio_ns3

#endif //!__UTILS__H__