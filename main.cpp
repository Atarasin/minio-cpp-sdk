#include "ilogger.hpp"
#include "minio_client.hpp"
#include "json/json.hpp"
#include <stdio.h>

using namespace minio_ns3;

int main() {

    // 对于自己搭建的服务器，http访问配置
    const char* server = "http://47.113.144.76:9000";
    const char* access_key = "vvx10M5LT5IJQBwI8Xg4";
    const char* secret_key = "79owWGirGT6sSC5molHDpgzdLoHwWpFiTQhcOuDJ";

    // 对于官方给的测试案例地址，https访问
    // const char* server     = "https://play.min.io:9000";
    // const char* access_key = "Q3AM3UQ867SPQQA43P2F";
    // const char* secret_key = "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG";
    MinioClient minio(server, access_key, secret_key);

    // int time_zone_to_gmt   = -8 * 3600;
    // const char* server     = "https://oss.ceph.com";
    // const char* access_key = "xxx";
    // const char* secret_key = "xxxxxx";
    // MinioClient minio(server, access_key, secret_key, time_zone_to_gmt);

    /////////////////////////////////////////////////////////////////
    INFO(
        "===========================test get buckets=========================");
    auto buckets = minio.get_bucket_list();
    INFO("total is %d", buckets.size());

    for (int i = 0; i < buckets.size(); ++i)
        INFO("bucket[%d] = %s", i, buckets[i].c_str());

    /////////////////////////////////////////////////////////////////
    INFO("===========================test upload=========================");
    const char* local_file = "../workspace/echo.txt";
    const char* bucket_name = buckets[0].c_str();
    if (minio.upload_file(iLogger::format("/%s/echo.txt", bucket_name),
                          local_file)) {
        INFO("upload %s success, size: %d bytes", local_file,
             iLogger::file_size(local_file));
    }

    /////////////////////////////////////////////////////////////////
    INFO("===========================test download=========================");
    auto data = minio.get_file(iLogger::format("/%s/echo.txt", bucket_name));
    INFO("download echo.txt, content is[%d bytes]: %s", data.size(),
         data.c_str());

    /////////////////////////////////////////////////////////////////
    INFO(
        "===========================test upload data=========================");
    auto filedata = iLogger::load_text_file("../workspace/echo.txt");
    if (minio.upload_filedata(
            iLogger::format("/%s/echo-filedata.txt", bucket_name), filedata)) {
        INFO("upload filedata success, filedata.size = %d", filedata.size());
    }

    /////////////////////////////////////////////////////////////////
    INFO("===========================test download=========================");
    auto data2 =
        minio.get_file(iLogger::format("/%s/echo-filedata.txt", bucket_name));
    INFO("download echo-filedata.txt, content is[%d bytes]: %s", data2.size(),
         data2.c_str());

    /////////////////////////////////////////////////////////////////
    INFO("===========================test preview=========================");
    auto preview_url =
        minio.get_file_preview_url(bucket_name, "2022-11-16.png", 24 * 60 * 60);
    INFO("preview url is: %s", preview_url.c_str());

    /////////////////////////////////////////////////////////////////
    INFO("===========================test upload=========================");
    auto post_res =
        minio.get_file_upload_url(bucket_name, "xxx.png", 24 * 60 * 60,
                                  {1 * 1024 * 1024, 10 * 1024 * 1024});
    INFO("post res is: %s", post_res.c_str());

    nlohmann::json json_res = nlohmann::json::parse(post_res);
    std::string upload_url = json_res["url"];

    return 0;
}