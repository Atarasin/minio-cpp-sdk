# minio-cpp-sdk，minio上传的C++API
- 基于调用libcurl和openssl，实现对minio操作
- 提交AWS的访问协议，实现对minio（创建bucket、查询bucket、上传、下载）
- 被AWS的cpp-sdk的65w个文件吓怕了，就想传个文件咋就这么难

# 示例代码
```C++
const char server     = "https://play.min.io:9000";
const char access_key = "Q3AM3UQ867SPQQA43P2F";
const char secret_key = "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG";
MinioClient minio(server, access_key, secret_key);

const char local_file = "echo.txt";
minio.upload_file("/test-bucket/echo.txt", local_file);
auto data = minio.get_file("/test-bucket/echo.txt");
```

# 使用
1. 配置openssl，下载并编译，例如：https://www.openssl.org/source/old/1.1.1/
2. 配置curl，配置具有ssl支持的curl，例如：https://curl.se/download.html
```bash
cd minio-cpp-sdk
mkdir build && cd build
cmake ..
```