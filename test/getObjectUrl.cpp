// MinIO C++ Library for Amazon S3 Compatible Cloud Storage
// Copyright 2022 MinIO, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "miniocpp/client.h"

int main(int argc, char* argv[]) {
  // Create S3 base URL.
  minio::s3::BaseUrl base_url("http://ip:port", false);

  // Create credential provider.
  minio::creds::StaticProvider provider(
      "AiEj4haD2O0KwVOsqPcA", "b8QLLjv1MxcyRfzlv5bbVQgo3vMblvrhq42bRjrw");

  // Create S3 client.
  minio::s3::Client client(base_url, &provider);

  client.Debug(true);

  // Create get presigned object url arguments.
  minio::s3::GetPresignedObjectUrlArgs args;
  args.bucket = "my-bucket";
  args.object = "my-object";
  args.method = minio::http::Method::kGet;
  args.expiry_seconds = 60 * 60 * 24;  // 1 day.

  // Call get presigned object url.
  minio::s3::GetPresignedObjectUrlResponse resp =
      client.GetPresignedObjectUrl(args);

  // Handle response.
  if (resp) {
    std::cout << "presigned URL to get object: " << resp.url << std::endl;
  } else {
    std::cout << "unable to get presigned object url; " << resp.Error().String()
              << std::endl;
  }

  return 0;
}
