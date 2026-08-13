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
import com.azure.identity.ClientSecretCredential;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.UserDelegationKey;
import com.azure.storage.blob.sas.BlobSasPermission;
import com.azure.storage.blob.sas.BlobServiceSasSignatureValues;
import com.azure.storage.blob.specialized.BlockBlobClient;
import com.azure.storage.common.policy.RequestRetryOptions;
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
 * Provider for service-principal authentication (tenant/client/secret). Builds a
 * {@link BlobServiceClient} once on construction and signs SAS tokens with a user
 * delegation key fetched from Azure.
 */
final class ServicePrincipalProvider extends AzureBlobContainerProviderV12 {

    private static final Logger log = LoggerFactory.getLogger(ServicePrincipalProvider.class);

    private final BlobServiceClient blobServiceClient;

    ServicePrincipalProvider(String containerName, HttpClient httpClient,
                              RequestRetryOptions retryOptions,
                              String accountName, String blobEndpoint,
                              ClientSecretCredential credential) {
        super(containerName, httpClient, retryOptions);
        BlobServiceClientBuilder builder = new BlobServiceClientBuilder()
                .endpoint(AzureBlobContainerProviderV12.getEndpointUrl(accountName, blobEndpoint))
                .credential(credential)
                .addPolicy(AzureHttpRequestLoggingPolicyV12.INSTANCE)
                .httpClient(httpClient);
        if (retryOptions != null) {
            builder.retryOptions(retryOptions);
        }
        this.blobServiceClient = builder.buildClient();
    }

    @Override
    @NotNull
    public BlobContainerClient getOrCreateBlobContainer() {
        log.debug("connecting to azure blob storage via service principal credentials");
        return blobServiceClient.getBlobContainerClient(containerName);
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
        BlockBlobClient blob = blobServiceClient.getBlobContainerClient(containerName)
                .getBlobClient(key).getBlockBlobClient();
        UserDelegationKey delegationKey = getOrRefreshDelegationKey(blobServiceClient, expiry);
        return blob.generateUserDelegationSas(values, delegationKey);
    }

    @Override
    boolean usesDelegationKeys() {
        return true;
    }

    @Override
    void close() {
        synchronized (cachedDelegationKey) {
            closed = true;
            cachedDelegationKey.set(null);
        }
    }
}
