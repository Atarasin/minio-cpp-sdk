#include "minio_client.hpp"
#include <openssl/hmac.h>
#include <string.h>

#include "http_client.hpp"
#include "ilogger.hpp"
#include "signer.hpp"
#include "utils.hpp"
#include "json/json.hpp"

namespace minio_ns3 {

static std::string base64_encode(const void* data, size_t size) {

    std::string encode_result;
    encode_result.reserve(size / 3 * 4 + (size % 3 != 0 ? 4 : 0));

    const unsigned char* current = static_cast<const unsigned char*>(data);
    static const char* base64_table =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    while (size > 2) {
        encode_result += base64_table[current[0] >> 2];
        encode_result +=
            base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
        encode_result +=
            base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
        encode_result += base64_table[current[2] & 0x3f];

        current += 3;
        size -= 3;
    }

    if (size > 0) {
        encode_result += base64_table[current[0] >> 2];
        if (size % 3 == 1) {
            encode_result += base64_table[(current[0] & 0x03) << 4];
            encode_result += "==";
        } else if (size % 3 == 2) {
            encode_result +=
                base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
            encode_result += base64_table[(current[1] & 0x0f) << 2];
            encode_result += "=";
        }
    }
    return encode_result;
}

// 与date -R 结果一致
static std::string gmtime_now(int correction_time) {
    time_t timet;
    time(&timet);
    timet += correction_time;

    tm& t = *(tm*)localtime(&timet);
    char timebuffer[100];
    strftime(timebuffer, sizeof(timebuffer), "%a, %d %b %Y %X %z", &t);
    return timebuffer;
}

// openssl sha1 -hmac -binary
static std::string hmac_encode_base64(const std::string& key, const void* data,
                                      size_t size) {

    // SHA1 needed 20 characters.
    unsigned int len = 20;
    unsigned char result[20];

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    // OpenSSL 1.1.1
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(&ctx, key.data(), key.size(), EVP_sha1(), NULL);
    HMAC_Update(&ctx, (unsigned char*)data, size);
    HMAC_Final(&ctx, result, &len);
    HMAC_CTX_free(ctx);
#else
    // OpenSSL 1.0.2
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key.data(), key.size(), EVP_sha1(), NULL);
    HMAC_Update(&ctx, (unsigned char*)data, size);
    HMAC_Final(&ctx, result, &len);
    HMAC_CTX_cleanup(&ctx);
#endif

    return base64_encode(result, len);
}

// echo -en ${_signature} | openssl sha1 -hmac ${s3_secret} -binary | base64
static std::string minio_hmac_encode(const std::string& hash_key,
                                     const std::string& method,
                                     const std::string& content_type,
                                     const std::string& time,
                                     const std::string& path) {
    char buffer[1000];
    int result_length =
        snprintf(buffer, sizeof(buffer), "%s\n\n%s\n%s\n%s", method.c_str(),
                 content_type.c_str(), time.c_str(), path.c_str());
    return hmac_encode_base64(hash_key, buffer, result_length);
}

static std::string extract_name(const std::string& response, int begin,
                                int end) {

    int p = response.find("<Name>", begin);
    if (p == -1 || p >= end)
        return "";
    p += 6;

    int e = response.find("</Name>", p);
    if (e == -1 || p >= e)
        return "";
    return std::string(response.begin() + p, response.begin() + e);
}

static std::vector<std::string> extract_buckets(const std::string& response) {

    std::string bucket_b_token = "<Bucket>";
    std::string bucket_e_token = "</Bucket>";
    std::vector<std::string> names;
    int p = response.find(bucket_b_token);
    while (p != -1) {
        int e = response.find(bucket_e_token, p + bucket_b_token.size());
        if (e == -1)
            break;

        names.emplace_back(move(extract_name(response, p, e)));
        p = response.find(bucket_b_token, e + bucket_e_token.size());
    }
    return names;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

MinioClient::MinioClient(const std::string& server,
                         const std::string& access_key,
                         const std::string& secret_key, int correction_time)
    : server(server), access_key(access_key), secret_key(secret_key),
      correction_time(correction_time) {}

bool MinioClient::upload_file(const std::string& remote_path,
                              const std::string& file) {
    const char* content_type = "application/octet-stream";
    auto time = gmtime_now(correction_time);
    auto signature =
        minio_hmac_encode(secret_key, "PUT", content_type, time, remote_path);

    auto http =
        newHttp(iLogger::format("%s%s", server.c_str(), remote_path.c_str()));
    bool success =
        http->add_header(iLogger::format("Date: %s", time.c_str()))
            ->add_header(iLogger::format("Content-Type: %s", content_type))
            ->add_header(iLogger::format("Authorization: AWS %s:%s",
                                         access_key.c_str(), signature.c_str()))
            ->put_file(file);

    if (!success) {
        INFOE("post failed: %s\n%s", http->error_message().c_str(),
              http->response_body().c_str());
    }
    return success;
}

bool MinioClient::upload_filedata(const std::string& remote_path,
                                  const std::string& filedata) {
    return upload_filedata(remote_path, filedata.data(), filedata.size());
}

bool MinioClient::upload_filedata(const std::string& remote_path,
                                  const void* file_data, size_t data_size) {
    const char* content_type = "application/octet-stream";
    auto time = gmtime_now(correction_time);
    auto signature =
        minio_hmac_encode(secret_key, "PUT", content_type, time, remote_path);

    auto http =
        newHttp(iLogger::format("%s%s", server.c_str(), remote_path.c_str()));
    bool success =
        http->add_header(iLogger::format("Date: %s", time.c_str()))
            ->add_header(iLogger::format("Content-Type: %s", content_type))
            ->add_header(iLogger::format("Authorization: AWS %s:%s",
                                         access_key.c_str(), signature.c_str()))
            ->put_body(HttpBodyData(file_data, data_size));

    if (!success) {
        INFOE("post failed: %s\n%s", http->error_message().c_str(),
              http->response_body().c_str());
    }
    return success;
}

bool MinioClient::make_bucket(const std::string& name) {

    std::string path = "/" + name;
    const char* content_type = "text/plane";

    auto time = gmtime_now(correction_time);
    auto signature =
        minio_hmac_encode(secret_key, "PUT", content_type, time, path);

    auto http = newHttp(iLogger::format("%s%s", server.c_str(), path.c_str()));
    bool success =
        http->add_header(iLogger::format("Date: %s", time.c_str()))
            ->add_header(iLogger::format("Content-Type: %s", content_type))
            ->add_header(iLogger::format("Authorization: AWS %s:%s",
                                         access_key.c_str(), signature.c_str()))
            ->put();

    if (!success) {
        INFOE("post failed: %s\n%s", http->error_message().c_str(),
              http->response_body().c_str());
    }
    return success;
}

std::vector<std::string> MinioClient::get_bucket_list(bool* pointer_success) {
    const char* path = "/";
    const char* content_type = "text/plane";

    auto time = gmtime_now(correction_time);
    auto signature =
        minio_hmac_encode(secret_key, "GET", content_type, time, path);

    auto http = newHttp(iLogger::format("%s%s", server.c_str(), path));
    bool success =
        http->add_header(iLogger::format("Date: %s", time.c_str()))
            ->add_header(iLogger::format("Content-Type: %s", content_type))
            ->add_header(iLogger::format("Authorization: AWS %s:%s",
                                         access_key.c_str(), signature.c_str()))
            ->get();

    if (pointer_success)
        *pointer_success = success;

    if (!success) {
        INFOE("post failed: %s\n%s", http->error_message().c_str(),
              http->response_body().c_str());
        return {};
    }
    return extract_buckets(http->response_body());
}

std::string MinioClient::get_file(const std::string& remote_path,
                                  bool* pointer_success) {
    const char* content_type = "application/octet-stream";
    auto time = gmtime_now(correction_time);
    auto signature =
        minio_hmac_encode(secret_key, "GET", content_type, time, remote_path);

    auto http =
        newHttp(iLogger::format("%s%s", server.c_str(), remote_path.c_str()));
    bool success =
        http->add_header(iLogger::format("Date: %s", time.c_str()))
            ->add_header(iLogger::format("Content-Type: %s", content_type))
            ->add_header(iLogger::format("Authorization: AWS %s:%s",
                                         access_key.c_str(), signature.c_str()))
            ->get();

    if (pointer_success)
        *pointer_success = success;

    if (!success) {
        INFOE("post failed: %s\n%s", http->error_message().c_str(),
              http->response_body().c_str());
        return "";
    }
    return http->response_body();
}

std::string MinioClient::get_file_preview_url(const std::string& bucket_name,
                                              const std::string& object_name,
                                              uint64_t expires_in_seconds,
                                              bool* pointer_success) {
    minio_ns3::utils::Multimap query_params;
    minio_ns3::utils::Time date = minio_ns3::utils::Time::Now();

    std::string url =
        iLogger::format("/%s/%s", bucket_name.c_str(), object_name.c_str());

    minio_ns3::signer::PresignV4("GET", "47.113.144.76", 9000, url,
                                 "cn-north-1", query_params, access_key,
                                 secret_key, date, expires_in_seconds);

    return server + url + "?" + query_params.ToQueryString();
}

std::string MinioClient::get_file_upload_url(
    const std::string& bucket_name, const std::string& key,
    uint64_t expires_in_seconds, std::pair<uint64_t, uint64_t> size_limit,
    bool* pointer_success) {
    nlohmann::json data;

    utils::Time expiration = utils::Time::Now();
    expiration.Add(expires_in_seconds);

    nlohmann::json policy;
    policy["expiration"] = expiration.ToISO8601UTC();

    nlohmann::json condition = nlohmann::json::array();
    condition.push_back({"eq", "$bucket", bucket_name});
    condition.push_back({"starts-with", "$key", key});

    if (size_limit.first > 0 && size_limit.second > 0) {
        condition.push_back(
            {"content-length-range", size_limit.first, size_limit.second});
    }

    utils::Time date = utils::Time::Now();
    std::string credential =
        signer::GetCredentialString(access_key, date, "cn-north-1");
    std::string amz_date = date.ToAmzDate();
    condition.push_back({"eq", "$x-amz-algorithm", "AWS4-HMAC-SHA256"});
    condition.push_back({"eq", "$x-amz-credential", credential});
    condition.push_back({"eq", "$x-amz-date", amz_date});

    policy["conditions"] = condition;

    std::string encoded_policy = utils::Base64Encode(policy.dump());
    std::string signature =
        signer::PostPresignV4(encoded_policy, secret_key, date, "cn-north-1");

    nlohmann::json form_data;
    form_data["x-amz-algorithm"] = "AWS4-HMAC-SHA256";
    form_data["x-amz-credential"] = credential;
    form_data["x-amz-date"] = amz_date;
    form_data["policy"] = encoded_policy;
    form_data["x-amz-signature"] = signature;

    data["url"] = iLogger::format("%s/%s", server.c_str(), bucket_name.c_str());
    data["form_data"] = form_data;

    return data.dump();
}

} // namespace minio_ns3
