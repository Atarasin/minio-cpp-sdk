#include "utils.hpp"

const std::string WEEK_DAYS[] = {"Sun", "Mon", "Tue", "Wed",
                                 "Thu", "Fri", "Sat"};
const std::string MONTHS[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
const std::regex MULTI_SPACE_REGEX("( +)");

namespace minio_ns3 {

namespace utils {

unsigned char ToHex(unsigned char x) { return x > 9 ? x + 55 : x + 48; }

unsigned char FromHex(unsigned char x) {
    unsigned char y;
    if (x >= 'A' && x <= 'Z')
        y = x - 'A' + 10;
    else if (x >= 'a' && x <= 'z')
        y = x - 'a' + 10;
    else if (x >= '0' && x <= '9')
        y = x - '0';
    else
        assert(0);
    return y;
}

std::string UrlEncode(const std::string& str) {
    std::string strTemp = "";
    size_t length = str.length();
    for (size_t i = 0; i < length; i++) {
        if (isalnum((unsigned char)str[i]) || (str[i] == '-') ||
            (str[i] == '_') || (str[i] == '.') || (str[i] == '~'))
            strTemp += str[i];
        else if (str[i] == ' ')
            strTemp += "+";
        else {
            strTemp += '%';
            strTemp += ToHex((unsigned char)str[i] >> 4);
            strTemp += ToHex((unsigned char)str[i] % 16);
        }
    }
    return strTemp;
}

std::string UrlDecode(const std::string& str) {
    std::string strTemp = "";
    size_t length = str.length();
    for (size_t i = 0; i < length; i++) {
        if (str[i] == '+')
            strTemp += ' ';
        else if (str[i] == '%') {
            assert(i + 2 < length);
            unsigned char high = FromHex((unsigned char)str[++i]);
            unsigned char low = FromHex((unsigned char)str[++i]);
            strTemp += high * 16 + low;
        } else
            strTemp += str[i];
    }
    return strTemp;
}

std::string FormatTime(const std::tm* time, const char* format) {
    char buf[128];
    std::strftime(buf, 128, format, time);
    return std::string(buf);
}

std::string ToLower(std::string str) {
    std::string s = str;
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

std::string Join(std::list<std::string> values, std::string delimiter) {
    std::string result;
    for (const auto& value : values) {
        if (!result.empty())
            result += delimiter;
        result += value;
    }
    return result;
}

std::string Join(std::vector<std::string> values, std::string delimiter) {
    std::string result;
    for (const auto& value : values) {
        if (!result.empty())
            result += delimiter;
        result += value;
    }
    return result;
}

// --------------------------------- cypher ---------------------------------

std::string Sha256Hash(std::string_view str) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    if (ctx == NULL) {
        std::cerr << "failed to create EVP_MD_CTX" << std::endl;
        std::terminate();
    }

    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL)) {
        std::cerr << "failed to init SHA-256 digest" << std::endl;
        std::terminate();
    }

    if (1 != EVP_DigestUpdate(ctx, str.data(), str.size())) {
        std::cerr << "failed to update digest" << std::endl;
        std::terminate();
    }

    unsigned int length = EVP_MD_size(EVP_sha256());
    unsigned char* digest = (unsigned char*)OPENSSL_malloc(length);
    if (digest == NULL) {
        std::cerr << "failed to allocate memory for hash value" << std::endl;
        std::terminate();
    }

    if (1 != EVP_DigestFinal_ex(ctx, digest, &length)) {
        OPENSSL_free(digest);
        std::cerr << "failed to finalize digest" << std::endl;
        std::terminate();
    }

    EVP_MD_CTX_destroy(ctx);

    std::string hash;
    char buf[3];
    for (int i = 0; i < length; ++i) {
        snprintf(buf, 3, "%02x", digest[i]);
        hash += buf;
    }

    OPENSSL_free(digest);

    return hash;
}

std::string Base64Encode(std::string_view str) {
    const auto base64_memory = BIO_new(BIO_s_mem());
    auto base64 = BIO_new(BIO_f_base64());
    base64 = BIO_push(base64, base64_memory);

    BIO_write(base64, str.data(), str.size());
    BIO_flush(base64);

    BUF_MEM* buf_mem{};
    BIO_get_mem_ptr(base64, &buf_mem);
    auto base64_encoded = std::string(buf_mem->data, buf_mem->length - 1);

    BIO_free_all(base64);

    return base64_encoded;
}

// --------------------------------- Time ---------------------------------
std::tm* Time::ToUTC() {
    std::tm* t = new std::tm;
    *t = utc_ ? *std::localtime(&tv_.tv_sec) : *std::gmtime(&tv_.tv_sec);
    return t;
}

std::string Time::ToSignerDate() {
    std::tm* utc = ToUTC();
    std::string result = FormatTime(utc, "%Y%m%d");
    delete utc;
    return result;
}

std::string Time::ToAmzDate() {
    std::tm* utc = ToUTC();
    std::string result = FormatTime(utc, "%Y%m%dT%H%M%SZ");
    delete utc;
    return result;
}

std::string Time::ToHttpHeaderValue() {
    std::tm* utc = ToUTC();
    std::stringstream ss;
    ss << WEEK_DAYS[utc->tm_wday] << ", " << FormatTime(utc, "%d ")
       << MONTHS[utc->tm_mon] << FormatTime(utc, " %Y %H:%M:%S GMT");
    return ss.str();
}

Time Time::FromHttpHeaderValue(const char* value) {
    std::string s(value);
    if (s.size() != 29)
        return Time();

    // Parse week day.
    auto pos =
        std::find(std::begin(WEEK_DAYS), std::end(WEEK_DAYS), s.substr(0, 3));
    if (pos == std::end(WEEK_DAYS))
        return Time();
    if (s.at(3) != ',')
        return Time();
    if (s.at(4) != ' ')
        return Time();
    auto week_day = pos - std::begin(WEEK_DAYS);

    // Parse day.
    std::tm day{0};
    strptime(s.substr(5, 2).c_str(), "%d", &day);
    if (s.at(7) != ' ')
        return Time();

    // Parse month.
    pos = std::find(std::begin(MONTHS), std::end(MONTHS), s.substr(8, 3));
    if (pos == std::end(MONTHS))
        return Time();
    auto month = pos - std::begin(MONTHS);

    // Parse rest of values.
    std::tm ltm{0};
    strptime(s.substr(11).c_str(), " %Y %H:%M:%S GMT", &ltm);
    ltm.tm_mday = day.tm_mday;
    ltm.tm_mon = month;

    // Validate week day.
    std::time_t time = std::mktime(&ltm);
    std::tm* t = std::localtime(&time);
    if (week_day != t->tm_wday)
        return Time();

    return Time(std::mktime(t), 0, true);
}

std::string Time::ToISO8601UTC() {
    char buf[64];
    snprintf(buf, 64, "%03ld", (long int)tv_.tv_usec);
    std::string usec_str(buf);
    if (usec_str.size() > 3)
        usec_str = usec_str.substr(0, 3);
    std::tm* utc = ToUTC();
    std::string result = FormatTime(utc, "%Y-%m-%dT%H:%M:%S.") + usec_str + "Z";
    delete utc;
    return result;
}

Time Time::FromISO8601UTC(const char* value) {
    std::tm t{0};
    char* rv = strptime(value, "%Y-%m-%dT%H:%M:%S", &t);
    unsigned long ul = 0;
    sscanf(rv, ".%lu", &ul);
    suseconds_t tv_usec = (suseconds_t)ul;
    std::time_t time = std::mktime(&t);
    return Time(time, tv_usec, true);
}

// --------------------------------- Multimap
// ---------------------------------
void Multimap::Add(std::string key, std::string value) {
    map_[key].insert(value);
    keys_[ToLower(key)].insert(key);
}

void Multimap::AddAll(const Multimap& headers) {
    auto m = headers.map_;
    for (auto& [key, values] : m) {
        map_[key].insert(values.begin(), values.end());
        keys_[ToLower(key)].insert(key);
    }
}

std::list<std::string> Multimap::ToHttpHeaders() {
    std::list<std::string> headers;
    for (auto& [key, values] : map_) {
        for (auto& value : values) {
            headers.push_back(key + ": " + value);
        }
    }
    return headers;
}

std::string Multimap::ToQueryString() {
    std::string query_string;
    for (auto& [key, values] : map_) {
        for (auto& value : values) {
            std::string s = UrlEncode(key) + "=" + UrlEncode(value);
            if (!query_string.empty())
                query_string += "&";
            query_string += s;
        }
    }
    return query_string;
}

bool Multimap::Contains(std::string_view key) {
    return keys_.find(ToLower(std::string(key))) != keys_.end();
}

std::list<std::string> Multimap::Get(std::string_view key) {
    std::list<std::string> result;
    std::set<std::string> keys = keys_[ToLower(std::string(key))];
    for (auto& key : keys) {
        std::set<std::string> values = map_[key];
        result.insert(result.end(), values.begin(), values.end());
    }
    return result;
}

std::string Multimap::GetFront(std::string_view key) {
    std::list<std::string> values = Get(key);
    return (values.size() > 0) ? values.front() : "";
}

std::list<std::string> Multimap::Keys() {
    std::list<std::string> keys;
    for (const auto& [key, _] : keys_)
        keys.push_back(key);
    return keys;
}

void Multimap::GetCanonicalHeaders(std::string& signed_headers,
                                   std::string& canonical_headers) {
    std::vector<std::string> signed_headerslist;
    std::map<std::string, std::string> map;

    for (auto& [k, values] : map_) {
        std::string key = ToLower(k);
        if ("authorization" == key || "user-agent" == key)
            continue;
        if (std::find(signed_headerslist.begin(), signed_headerslist.end(),
                      key) == signed_headerslist.end()) {
            signed_headerslist.push_back(key);
        }

        std::string value;
        for (auto& v : values) {
            if (!value.empty())
                value += ",";
            value += std::regex_replace(v, MULTI_SPACE_REGEX, " ");
        }

        map[key] = value;
    }

    std::sort(signed_headerslist.begin(), signed_headerslist.end());
    signed_headers = utils::Join(signed_headerslist, ";");

    std::vector<std::string> canonical_headerslist;
    for (auto& [key, value] : map) {
        canonical_headerslist.push_back(key + ":" + value);
    }

    std::sort(canonical_headerslist.begin(), canonical_headerslist.end());
    canonical_headers = utils::Join(canonical_headerslist, "\n");
}

std::string Multimap::GetCanonicalQueryString() {
    std::vector<std::string> keys;
    for (auto& [key, _] : map_)
        keys.push_back(key);
    std::sort(keys.begin(), keys.end());

    std::vector<std::string> values;
    for (auto& key : keys) {
        auto vals = map_[key];
        for (auto& value : vals) {
            std::string s = UrlEncode(key) + "=" + UrlEncode(value);
            values.push_back(s);
        }
    }

    return utils::Join(values, "&");
}

} // namespace utils

} // namespace minio_ns3
