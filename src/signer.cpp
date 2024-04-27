#include "signer.hpp"

const char* SIGN_V4_ALGORITHM = "AWS4-HMAC-SHA256";

namespace minio_ns3 {

namespace signer {

std::string GetScope(utils::Time& time, const std::string& region,
                     const std::string& service_name) {
    return time.ToSignerDate() + "/" + region + "/" + service_name +
           "/aws4_request";
}

std::string GetCredentialString(const std::string& access_key, utils::Time date,
                                std::string region) {
    return access_key + "/" + date.ToSignerDate() + "/" + region +
           "/s3/aws4_request";
}

std::string GetCanonicalRequestHash(const std::string& method,
                                    const std::string& uri,
                                    const std::string& query_string,
                                    const std::string& headers,
                                    const std::string& signed_headers,
                                    const std::string& content_sha256) {
    std::string canonical_request = method + "\n" + uri + "\n" + query_string +
                                    "\n" + headers + "\n\n" + signed_headers +
                                    "\n" + content_sha256;
    std::cout << "canonical_request: " << canonical_request << std::endl;
    return utils::Sha256Hash(canonical_request);
}

std::string GetStringToSign(utils::Time& date, const std::string& scope,
                            const std::string& canonical_request_hash) {
    return "AWS4-HMAC-SHA256\n" + date.ToAmzDate() + "\n" + scope + "\n" +
           canonical_request_hash;
}

std::string HmacHash(std::string_view key, std::string_view data) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> hash;
    unsigned int hash_len;

    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<unsigned char const*>(data.data()),
         static_cast<int>(data.size()), hash.data(), &hash_len);

    return std::string{reinterpret_cast<char const*>(hash.data()), hash_len};
}

std::string GetSigningKey(const std::string& secret_key, utils::Time& date,
                          std::string_view region,
                          std::string_view service_name) {
    std::string date_key = HmacHash("AWS4" + secret_key, date.ToSignerDate());
    std::string date_region_key = HmacHash(date_key, region);
    std::string date_region_service_key =
        HmacHash(date_region_key, service_name);
    return HmacHash(date_region_service_key, "aws4_request");
}

std::string GetSignature(std::string_view signing_key,
                         std::string_view string_to_sign) {
    std::string hash = HmacHash(signing_key, string_to_sign);
    std::string signature;
    char buf[3];
    for (int i = 0; i < hash.size(); ++i) {
        snprintf(buf, 3, "%02x", (unsigned char)hash[i]);
        signature += buf;
    }
    return signature;
}

std::string GetAuthorization(const std::string& access_key,
                             const std::string& scope,
                             const std::string& signed_headers,
                             const std::string& signature) {
    return "AWS4-HMAC-SHA256 Credential=" + access_key + "/" + scope + ", " +
           "SignedHeaders=" + signed_headers + ", " + "Signature=" + signature;
}

utils::Multimap&
PresignV4(const std::string& method, const std::string& host, int port,
          const std::string& uri, const std::string& region,
          utils::Multimap& query_params, const std::string& access_key,
          std::string& secret_key, utils::Time& date, unsigned int expires) {
    std::string service_name = "s3";
    std::string scope = GetScope(date, region, service_name);
    std::string canonical_headers = "host:" + host + ":" + std::to_string(port);
    std::string signed_headers = "host";

    query_params.Add("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
    query_params.Add("X-Amz-Credential", access_key + "/" + scope);
    query_params.Add("X-Amz-Date", date.ToAmzDate());
    query_params.Add("X-Amz-Expires", std::to_string(expires));
    query_params.Add("X-Amz-SignedHeaders", signed_headers);
    std::string canonical_query_string = query_params.GetCanonicalQueryString();
    std::string methodstring = method;
    std::string content_sha256 = "UNSIGNED-PAYLOAD";
    std::string canonical_request_hash = GetCanonicalRequestHash(
        methodstring, uri, canonical_query_string, canonical_headers,
        signed_headers, content_sha256);

    std::string string_to_sign =
        GetStringToSign(date, scope, canonical_request_hash);
    std::string signing_key =
        GetSigningKey(secret_key, date, region, service_name);
    std::string signature = GetSignature(signing_key, string_to_sign);
    query_params.Add("X-Amz-Signature", signature);
    return query_params;
}

std::string PostPresignV4(const std::string& string_to_sign,
                          const std::string& secret_key, utils::Time& date,
                          const std::string& region) {
    std::string service_name = "s3";
    std::string signing_key =
        GetSigningKey(secret_key, date, region, service_name);
    return GetSignature(signing_key, string_to_sign);
}

} // namespace signer

} // namespace minio_ns3
