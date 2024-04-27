#ifndef __SIGNER__H__
#define __SIGNER__H__

#include "utils.hpp"
#include <iostream>
#include <string>
#include <string_view>

namespace minio_ns3 {

namespace signer {

std::string GetScope(utils::Time& time, const std::string& region,
                     const std::string& service_name);
std::string GetCredentialString(const std::string& access_key, utils::Time date,
                                std::string region);
std::string GetCanonicalRequestHash(
    const std::string& method, // GET, POST, etc.
    const std::string& uri,    // /bucket/object
    const std::string&
        query_string, // X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=vvx10M5LT5IJQBwI8Xg4%2F20240426%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240426T153315Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host
    const std::string& headers,         // host:ip:port
    const std::string& signed_headers,  // host
    const std::string& content_sha256); // UNSIGNED-PAYLOAD
std::string GetStringToSign(utils::Time& date, const std::string& scope,
                            const std::string& canonical_request_hash);
std::string HmacHash(std::string_view key, std::string_view data);
std::string GetSigningKey(const std::string& secret_key, utils::Time& date,
                          std::string_view region,
                          std::string_view service_name);
std::string GetSignature(std::string_view signing_key,
                         std::string_view string_to_sign);
std::string GetAuthorization(const std::string& access_key,
                             const std::string& scope,
                             const std::string& signed_headers,
                             const std::string& signature);

utils::Multimap&
PresignV4(const std::string& method, const std::string& host, int port,
          const std::string& uri, const std::string& region,
          utils::Multimap& query_params, const std::string& access_key,
          std::string& secret_key, utils::Time& date, unsigned int expires);

std::string PostPresignV4(const std::string& string_to_sign,
                          const std::string& secret_key, utils::Time& date,
                          const std::string& region);

} // namespace signer

} // namespace minio_ns3

#endif //!__SIGNER__H__