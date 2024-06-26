/**
 * @file minio_client.cpp
 * @author 手写AI
 *         我们的B站：https://space.bilibili.com/1413433465/
 *         我们的博客：http://zifuture.com:8090
 *
 * @brief
 * 基于CURL提交AWS的访问协议，实现对minio进行操作（创建bucket、查询bucket、上传、下载）
 *         被AWS的cpp-sdk的65w个文件吓怕了，就想传个文件咋就这么难
 *
 * @date 2021年7月28日 17:56:02
 *
 *   注意，主要分析手段，是使用minio的js-sdk看他提交http时给的参数是什么，进而估计出C++应该怎么写
 *   minio的js-sdk用的签名方式不同（是AWS4-HMAC-SHA256），如果能完全模拟他，就好了
 *
 *   参考：
 *   1. https://github.com/minio/minio/issues/8136
 *   2. https://github.com/kneufeld/minio-put
 *   3. https://docs.min.io/docs/javascript-client-quickstart-guide.html
 *   4. https://github.com/minio/minio-js/blob/master/src/main/minio.js
 */

#ifndef MINIO_CLIENT_HPP
#define MINIO_CLIENT_HPP

#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace minio_ns3 {

class MinioClient {
public:
    /**
     * @brief 创建一个minio的客户端
     *     这个类实际上没干嘛，仅仅是记录3个字符串避免重复传参数
     *     每个函数都是独立运行的，可以允许多线程
     *
     * @param server 指定服务器地址，例如：http://127.0.0.1:9000，注意不要多斜杠
     * @param access_key    指定访问的key，例如：F2IHVVX44WVGYUIA1ESX
     * @param secret_key
     * 指定加密的key，例如：UiJuXEG4V6ZLqCZ9ZbD9lqKEG8WwtaKeA3kh7Lui
     */
    explicit MinioClient(const std::string& server,
                         const std::string& access_key,
                         const std::string& secret_key,
                         const std::string& region = "cn-north-1",
                         int correction_time = 0);

    /**
     * @brief 上传文件到minio服务器-通过文件路径
     *
     * @param remote_path
     * 指定远程路径，bucket也包含在内，例如：/test-bucket/wish/wish235.txt
     * @param file         指定本地的文件路径，例如：echo.txt
     * @return 如果成功返回true，否则返回false并打印消息
     */
    bool upload_file(const std::string& remote_path, const std::string& file);

    /**
     * @brief 上传文件到minio服务器-通过文件数据
     *
     * @param remote_path
     * 指定远程路径，bucket也包含在内，例如：/test-bucket/wish/wish235.txt
     * @param file         指定本地的文件路径，例如：echo.txt
     * @return 如果成功返回true，否则返回false并打印消息
     */
    bool upload_filedata(const std::string& remote_path,
                         const std::string& file_data);

    /**
     * @brief 上传文件到minio服务器-通过文件数据
     *
     * @param remote_path
     * 指定远程路径，bucket也包含在内，例如：/test-bucket/wish/wish235.txt
     * @param file         指定本地的文件路径，例如：echo.txt
     * @return 如果成功返回true，否则返回false并打印消息
     */
    bool upload_filedata(const std::string& remote_path, const void* file_data,
                         size_t data_size);

    /**
     * @brief 获取服务器bucket列表
     *
     * @return std::vector<std::string>
     */
    std::vector<std::string> get_bucket_list(bool* pointer_success = nullptr);

    /**
     * @brief 创建新的bucket，如果已经存在会报错
     *
     * @param name           指定bucket的名字，例如：test-bucket
     * @return true
     * @return false
     */
    bool make_bucket(const std::string& name);

    /**
     * @brief 下载读取文件数据
     *
     * @param remote_path
     * 指定远程路径，bucket也包含在内，例如：/test-bucket/wish/wish235.txt
     * @return std::string
     * 返回文件数据，string类型打包的，string.data()是指针，string.size()是长度
     */
    std::string get_file(const std::string& remote_path,
                         bool* pointer_success = nullptr);

    /**
     * @brief 获取文件预览地址
     *
     * @param bucket_name
     * 指定bucket的名字，例如：test-bucket
     * @param object_name
     * 指定文件名，例如：wish/wish235.txt
     * @param expires_in_seconds
     * 指定过期时间，单位秒，例如：60*60*24*30，表示30天
     * @return std::string
     * 返回文件预览地址，例如：http://127.0.0.1:9000/test-bucket/wish/wish235.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=F2IHVVX44WVGYUIA1ESX%2F20210728%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20210728T175602Z&X-Amz-Expires=30&X-Amz-SignedHeaders=host&X-Amz-Signature=1a7d55d5
     */
    std::string get_file_preview_url(const std::string& bucket_name,
                                     const std::string& object_name,
                                     uint64_t expires_in_seconds,
                                     bool* pointer_success = nullptr);

    /**
     * @brief 获取文件上传地址
     *
     * @param bucket_name
     * 指定bucket的名字，例如：test-bucket
     * @param key
     * 指定文件名，例如：wish/wish235.txt
     * @param expires_in_seconds
     * 指定过期时间，单位秒，例如：60*60*24*30，表示30天
     * @param size_limit
     * 指定文件大小限制，单位字节，例如：std::make_pair(1024*1024,
     * 1024*1024*1024)表示1M到1G
     * @return std::map<std::string, std::string>
     * 返回文件上传地址和表单数据，例如：
     * {
     *     "url": "http://127.0.0.1:9000/test-bucket/wish/wish235.txt",
     *     "key": "wish/wish235.txt",
     *     "x-amz-algorithm": "AWS4-HMAC-SHA256",
     *     "x-amz-credential":
     * "F2IHVVX44WVGYUIA1ESX/20210728/us-east-1/s3/aws4_request", "x-amz-date":
     * "20210728T175602Z"
     * }
     */
    std::map<std::string, std::string> get_file_upload_form_data(
        const std::string& bucket_name, const std::string& key,
        uint64_t expires_in_seconds, std::pair<uint64_t, uint64_t> size_limit,
        bool* pointer_success = nullptr);

private:
    std::string server_;
    std::string host_;
    int port_;
    bool use_https_;
    std::string access_key_;
    std::string secret_key_;
    std::string region_;
    int correction_time_;
};

} // namespace minio_ns3

#endif // MINIO_CLIENT_HPP
