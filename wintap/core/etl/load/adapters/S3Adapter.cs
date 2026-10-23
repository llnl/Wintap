using Amazon.Runtime;
using Amazon.S3;
using Amazon.S3.Model;
using gov.llnl.wintap.core.etl.load.adapters.baseclass;
using gov.llnl.wintap.core.etl.load.interfaces;
using gov.llnl.wintap.core.infrastructure;
using gov.llnl.wintap.core.shared;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace gov.llnl.wintap.core.etl.load.adapters
{
    internal class S3Adapter : Uploader, IUpload
    {
        private AWSCredentials awsCredentials;
        private AmazonS3Client client;

        public bool PostUpload()
        {
            WintapLogger.Log.Append(this.Name + " post upload method called", LogLevel.Info);
            client?.Dispose();
            client = null;
            this.stopSessionStats();
            return true;
        }

        public bool PreUpload(Dictionary<string, string> parameters)
        {
            WintapLogger.Log.Append(" PreUpload method called", LogLevel.Info);

            awsCredentials = createCredentials(parameters);
            AmazonS3Config s3Config = createS3Config(parameters);
            configureCloudflareAccess(parameters, s3Config);
            client = new AmazonS3Client(awsCredentials, s3Config);

            this.startSessionStats();
            WintapLogger.Log.Append(" PreUpload method complete", LogLevel.Info);
            return true;
        }

        public async Task<bool> Upload(string localFile, Dictionary<string, string> parameters)
        {
            WintapLogger.Log.Append(this.Name + " upload method called", LogLevel.Info);
            bool fileSent = false;

            string bucketName = getParameter(parameters, "Bucket");
            if (string.IsNullOrWhiteSpace(bucketName))
            {
                throw new Exception("NO_BUCKET_SPECIFIED");
            }

            WintapLogger.Log.Append("Bucket: " + bucketName, LogLevel.Info);

            FileInfo localFileInfo = new FileInfo(localFile);
            if (!localFileInfo.Exists)
            {
                throw new FileNotFoundException("Local file does not exist", localFile);
            }

            string objectKey = getS3ObjectNameForFile(localFileInfo.FullName, parameters);
            WintapLogger.Log.Append("s3 object key: " + objectKey, LogLevel.Info);

            if (bucketName != "NONE")
            {
                PutObjectRequest req = new PutObjectRequest
                {
                    BucketName = bucketName,
                    Key = objectKey,
                    FilePath = localFile
                };

                req.Metadata.Add("ComputerName", Environment.MachineName);
                req.Metadata.Add("Timestamp", DateTime.Now.ToFileTimeUtc().ToString());
                req.CannedACL = S3CannedACL.BucketOwnerFullControl;

                try
                {
                    PutObjectResponse resp = await putObjectWithRateLimitRetry(req, parameters);
                    fileSent = true;
                    updateSessionStats();
                    WintapLogger.Log.Append("Upload HTTP status code: " + resp.HttpStatusCode, LogLevel.Info);
                }
                catch (Exception ex)
                {
                    WintapLogger.Log.Append("Upload failed: " + ex.Message, LogLevel.Warn);
                    fileSent = false;
                }
            }

            return fileSent;
        }

        private AWSCredentials createCredentials(Dictionary<string, string> parameters)
        {
            string accessKey = getParameter(parameters, "AccessKey");
            string secretKey = getParameter(parameters, "SecretKey");
            string sessionToken = getParameter(parameters, "SessionToken");

            if (!string.IsNullOrWhiteSpace(accessKey) && !string.IsNullOrWhiteSpace(secretKey))
            {
                WintapLogger.Log.Append("Using S3 credentials from ETLConfig AccessKey/SecretKey", LogLevel.Info);
                if (!string.IsNullOrWhiteSpace(sessionToken))
                {
                    return new SessionAWSCredentials(accessKey, secretKey, sessionToken);
                }

                return new BasicAWSCredentials(accessKey, secretKey);
            }

            WintapLogger.Log.Append("Using S3 instance profile credentials", LogLevel.Info);
            return new InstanceProfileAWSCredentials();
        }

        private async Task<PutObjectResponse> putObjectWithRateLimitRetry(PutObjectRequest request, Dictionary<string, string> parameters)
        {
            int maxRetries = getIntParameter(parameters, "RateLimitMaxRetries", 5);
            int initialDelayMs = getIntParameter(parameters, "RateLimitInitialDelayMs", 1000);
            int maxDelayMs = getIntParameter(parameters, "RateLimitMaxDelayMs", 60000);
            int attempt = 0;

            while (true)
            {
                try
                {
                    return await client.PutObjectAsync(request);
                }
                catch (AmazonServiceException ex) when (IsRateLimitResponse(ex) && attempt < maxRetries)
                {
                    attempt++;
                    int delayMs = CalculateBackoffDelayMs(attempt, initialDelayMs, maxDelayMs);
                    WintapLogger.Log.Append($"S3 upload was rate limited with HTTP 429. Retry {attempt}/{maxRetries} in {delayMs} ms. Message: {ex.Message}", LogLevel.Warn);
                    await Task.Delay(delayMs);
                }
            }
        }

        private bool IsRateLimitResponse(AmazonServiceException ex)
        {
            return ex.StatusCode == (HttpStatusCode)429 || ex.StatusCode == HttpStatusCode.TooManyRequests;
        }

        private int CalculateBackoffDelayMs(int attempt, int initialDelayMs, int maxDelayMs)
        {
            int boundedInitialDelay = Math.Max(initialDelayMs, 100);
            int boundedMaxDelay = Math.Max(maxDelayMs, boundedInitialDelay);
            double exponentialDelay = boundedInitialDelay * Math.Pow(2, attempt - 1);
            int delay = (int)Math.Min(exponentialDelay, boundedMaxDelay);
            int jitter = Random.Shared.Next(0, Math.Max(1, delay / 4));
            return Math.Min(delay + jitter, boundedMaxDelay);
        }

        private int getIntParameter(Dictionary<string, string> parameters, string key, int defaultValue)
        {
            string value = getParameter(parameters, key);
            if (int.TryParse(value, out int parsed) && parsed >= 0)
            {
                return parsed;
            }

            return defaultValue;
        }

        private void configureCloudflareAccess(Dictionary<string, string> parameters, AmazonS3Config s3Config)
        {
            string clientId = getParameter(parameters, "CloudflareAccessClientId");
            if (string.IsNullOrWhiteSpace(clientId))
            {
                clientId = getParameter(parameters, "CFAccessClientId");
            }
            if (string.IsNullOrWhiteSpace(clientId))
            {
                clientId = ConfigManager.GetValue<string>("CF_ACCESS_CLIENT_ID");
            }

            string clientSecret = getParameter(parameters, "CloudflareAccessClientSecret");
            if (string.IsNullOrWhiteSpace(clientSecret))
            {
                clientSecret = getParameter(parameters, "CFAccessClientSecret");
            }
            if (string.IsNullOrWhiteSpace(clientSecret))
            {
                clientSecret = ConfigManager.GetValue<string>("CF_ACCESS_CLIENT_SECRET");
            }

            if (string.IsNullOrWhiteSpace(clientId) && string.IsNullOrWhiteSpace(clientSecret))
            {
                return;
            }

            if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(clientSecret))
            {
                WintapLogger.Log.Append("Cloudflare Access service token configuration is incomplete. Both client id and client secret are required.", LogLevel.Warn);
                return;
            }

            s3Config.HttpClientFactory = new CloudflareAccessHttpClientFactory(clientId, clientSecret);
            WintapLogger.Log.Append("Cloudflare Access service token headers are enabled for S3 uploads", LogLevel.Info);
        }

        private AmazonS3Config createS3Config(Dictionary<string, string> parameters)
        {
            string regionEndpoint = getParameter(parameters, "RegionEndpoint");
            string serviceUrl = getParameter(parameters, "ServiceURL");
            if (string.IsNullOrWhiteSpace(serviceUrl))
            {
                serviceUrl = getParameter(parameters, "Endpoint");
            }

            AmazonS3Config config = new AmazonS3Config();

            if (!string.IsNullOrWhiteSpace(serviceUrl))
            {
                config.ServiceURL = serviceUrl;
                if (Uri.TryCreate(serviceUrl, UriKind.Absolute, out var endpointUri) &&
                    !endpointUri.Host.Equals("amazonaws.com", StringComparison.OrdinalIgnoreCase) &&
                    !endpointUri.Host.EndsWith(".amazonaws.com", StringComparison.OrdinalIgnoreCase))
                {
                    config.RequestChecksumCalculation = RequestChecksumCalculation.WHEN_REQUIRED;
                    config.ResponseChecksumValidation = ResponseChecksumValidation.WHEN_REQUIRED;
                }
                WintapLogger.Log.Append("Using S3 service URL: " + serviceUrl, LogLevel.Info);

                if (!string.IsNullOrWhiteSpace(regionEndpoint))
                {
                    config.AuthenticationRegion = regionEndpoint;
                }
            }
            else if (!string.IsNullOrWhiteSpace(regionEndpoint))
            {
                config.RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(regionEndpoint);
                WintapLogger.Log.Append("Using S3 region endpoint: " + regionEndpoint, LogLevel.Info);
            }

            // S3-compatible/on-prem endpoints often do not have wildcard DNS for virtual-host bucket addressing.
            // If ForcePathStyle isn't explicitly set and this isn't an AWS host, default to path-style to avoid
            // hostname lookups like: <bucket>.<host>.
            string forcePathStyleRaw = getParameter(parameters, "ForcePathStyle");
            if (bool.TryParse(forcePathStyleRaw, out bool forcePathStyle))
            {
                config.ForcePathStyle = forcePathStyle;
                WintapLogger.Log.Append("S3 ForcePathStyle: " + config.ForcePathStyle, LogLevel.Info);
            }
            else if (string.IsNullOrWhiteSpace(forcePathStyleRaw) && !string.IsNullOrWhiteSpace(serviceUrl))
            {
                try
                {
                    var uri = new Uri(serviceUrl);
                    bool isAwsHost = uri.Host.Equals("amazonaws.com", StringComparison.OrdinalIgnoreCase) ||
                        uri.Host.EndsWith(".amazonaws.com", StringComparison.OrdinalIgnoreCase);
                    if (!isAwsHost)
                    {
                        config.ForcePathStyle = true;
                        WintapLogger.Log.Append("S3 ForcePathStyle defaulted to true for non-AWS ServiceURL host: " + uri.Host, LogLevel.Info);
                    }
                }
                catch
                {
                    // Keep SDK default behavior if the URL can't be parsed.
                }
            }

            return config;
        }

        private class CloudflareAccessHttpClientFactory : Amazon.Runtime.HttpClientFactory
        {
            private readonly string clientId;
            private readonly string clientSecret;

            internal CloudflareAccessHttpClientFactory(string clientId, string clientSecret)
            {
                this.clientId = clientId;
                this.clientSecret = clientSecret;
            }

            public override HttpClient CreateHttpClient(Amazon.Runtime.IClientConfig clientConfig)
            {
                HttpMessageHandler innerHandler = new HttpClientHandler();
                HttpMessageHandler cloudflareAccessHandler = new CloudflareAccessHeaderHandler(clientId, clientSecret)
                {
                    InnerHandler = innerHandler
                };

                return new HttpClient(cloudflareAccessHandler);
            }
        }

        private class CloudflareAccessHeaderHandler : DelegatingHandler
        {
            private readonly string clientId;
            private readonly string clientSecret;

            internal CloudflareAccessHeaderHandler(string clientId, string clientSecret)
            {
                this.clientId = clientId;
                this.clientSecret = clientSecret;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                request.Headers.Remove("CF-Access-Client-Id");
                request.Headers.Remove("CF-Access-Client-Secret");
                request.Headers.TryAddWithoutValidation("CF-Access-Client-Id", clientId);
                request.Headers.TryAddWithoutValidation("CF-Access-Client-Secret", clientSecret);

                return base.SendAsync(request, cancellationToken);
            }
        }
    }
}
