/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.jackrabbit.oak.blob.cloud.azure.blobstorage.v12;

import com.azure.core.http.HttpClient;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.sas.BlobSasPermission;
import com.azure.storage.blob.sas.BlobServiceSasSignatureValues;
import com.azure.storage.blob.specialized.BlockBlobClient;
import com.azure.storage.common.policy.RequestRetryOptions;
import org.apache.commons.lang3.StringUtils;
import org.apache.jackrabbit.oak.spi.blob.data.DataStoreException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Provider for connection-string, SAS token, or account-key authentication. Builds a
 * {@link BlobContainerClient} on each {@link #getOrCreateBlobContainer()} call and signs
 * SAS tokens with the account key.
 */
final class SharedKeyProvider extends AzureBlobContainerProviderV12 {

    private static final Logger log = LoggerFactory.getLogger(SharedKeyProvider.class);

    private final String azureConnectionString;
    private final String accountName;
    private final String blobEndpoint;
    private final String sasToken;
    private final String accountKey;

    SharedKeyProvider(String containerName, HttpClient httpClient,
                       RequestRetryOptions retryOptions,
                       String azureConnectionString, String accountName,
                       String blobEndpoint, String sasToken, String accountKey) {
        super(containerName, httpClient, retryOptions);
        this.azureConnectionString = azureConnectionString;
        this.accountName = accountName;
        this.blobEndpoint = blobEndpoint;
        this.sasToken = sasToken;
        this.accountKey = accountKey;
    }

    @Override
    @Nullable
    public String getAzureConnectionString() {
        return azureConnectionString;
    }

    @Override
    @NotNull
    public BlobContainerClient getOrCreateBlobContainer() throws DataStoreException {
        if (StringUtils.isNotBlank(azureConnectionString)) {
            log.debug("connecting to azure blob storage via azureConnectionString");
            return UtilsV12.createBlobContainerFromConnectionString(azureConnectionString, containerName, retryOptions, httpClient);
        } else if (StringUtils.isNotBlank(sasToken)) {
            log.debug("connecting to azure blob storage via sas token");
            String cs = UtilsV12.createConnectionStringForSas(sasToken, blobEndpoint, accountName);
            return UtilsV12.createBlobContainerFromConnectionString(cs, containerName, retryOptions, httpClient);
        }
        log.debug("connecting to azure blob storage via access key");
        String cs = UtilsV12.createConnectionString(accountName, accountKey, blobEndpoint);
        return UtilsV12.createBlobContainerFromConnectionString(cs, containerName, retryOptions, httpClient);
    }

    @Override
    @NotNull
    public String generateSharedAccessSignature(String key,
                                                 BlobSasPermission blobSasPermissions,
                                                 int expirySeconds,
                                                 @Nullable BlobSasHeadersV12 optionalHeaders)
            throws DataStoreException, URISyntaxException, InvalidKeyException {
        OffsetDateTime expiry = OffsetDateTime.now(ZoneOffset.UTC).plusSeconds(expirySeconds);
        BlobServiceSasSignatureValues values = new BlobServiceSasSignatureValues(expiry, blobSasPermissions);
        if (optionalHeaders != null) {
            optionalHeaders.applyTo(values);
        }
        BlockBlobClient blob = getOrCreateBlobContainer().getBlobClient(key).getBlockBlobClient();
        return blob.generateSas(values, null);
    }
}
