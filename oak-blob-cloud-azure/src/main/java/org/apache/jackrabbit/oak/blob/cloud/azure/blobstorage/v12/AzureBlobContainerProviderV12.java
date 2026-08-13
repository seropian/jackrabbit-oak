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
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.identity.ClientSecretCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.storage.blob.BlobContainerClient;
import com.azure.storage.blob.BlobServiceClient;
import com.azure.storage.blob.BlobServiceClientBuilder;
import com.azure.storage.blob.models.UserDelegationKey;
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
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Provides an authenticated {@link BlobContainerClient} and presigned SAS generation for Azure
 * Blob Storage. Abstract base; {@link ServicePrincipalProvider} handles service-principal auth
 * (user delegation keys), {@link SharedKeyProvider} handles connection strings, SAS tokens, and
 * account keys. The {@link Builder} picks the concrete type based on the supplied credentials.
 */
abstract class AzureBlobContainerProviderV12 {

    private static final Logger log = LoggerFactory.getLogger(AzureBlobContainerProviderV12.class);
    private static final String DEFAULT_ENDPOINT_SUFFIX = "core.windows.net";

    static final Duration DELEGATION_KEY_LIFETIME = Duration.ofDays(7);
    private static final Duration DELEGATION_KEY_RENEWAL_BUFFER = Duration.ofSeconds(60);

    // Shared state accessible to both subclasses and tests via the base type.
    protected final String containerName;
    final HttpClient httpClient;
    final RequestRetryOptions retryOptions;
    // Delegation-key cache — only used by ServicePrincipalProvider but kept here so tests can
    // inject and inspect it via the base-type reference without casting.
    final AtomicReference<CachedDelegationKey> cachedDelegationKey = new AtomicReference<>();
    volatile boolean closed = false;

    protected AzureBlobContainerProviderV12(String containerName, HttpClient httpClient,
                                             RequestRetryOptions retryOptions) {
        this.containerName = containerName;
        this.httpClient = httpClient;
        this.retryOptions = retryOptions;
    }

    public String getContainerName() {
        return containerName;
    }

    /** Returns the configured connection string, or {@code null} for service-principal providers. */
    @Nullable
    public String getAzureConnectionString() {
        return null;
    }

    @NotNull
    public abstract BlobContainerClient getOrCreateBlobContainer() throws DataStoreException;

    @NotNull
    public abstract String generateSharedAccessSignature(String key,
                                                          BlobSasPermission blobSasPermissions,
                                                          int expirySeconds,
                                                          @Nullable BlobSasHeadersV12 optionalHeaders)
            throws DataStoreException, URISyntaxException, InvalidKeyException;

    /**
     * True when SAS tokens are signed with a user delegation key (service-principal auth).
     * Used to enforce the 7-day cap on presigned URI expiry.
     */
    boolean usesDelegationKeys() {
        return false;
    }

    void close() {
        closed = true;
    }

    /**
     * Returns a cached {@link UserDelegationKey} valid past {@code sasExpiry}, fetching a fresh
     * one when the cache is cold or the cached key would expire too soon. The key is always
     * requested for {@link #DELEGATION_KEY_LIFETIME} (7 days) so it covers any SAS expiry we
     * would generate without frequent round-trips to Azure.
     */
    UserDelegationKey getOrRefreshDelegationKey(BlobServiceClient blobServiceClient, OffsetDateTime sasExpiry) {
        // Fast path: cached key still covers sasExpiry with headroom.
        CachedDelegationKey cached = cachedDelegationKey.get();
        if (cached != null && cached.expiry.isAfter(sasExpiry.plus(DELEGATION_KEY_RENEWAL_BUFFER))) {
            return cached.key;
        }
        synchronized (cachedDelegationKey) {
            if (closed) {
                throw new IllegalStateException("AzureBlobContainerProviderV12 is closed");
            }
            // Re-check inside the lock — another thread may have refreshed while we waited.
            cached = cachedDelegationKey.get();
            if (cached != null && cached.expiry.isAfter(sasExpiry.plus(DELEGATION_KEY_RENEWAL_BUFFER))) {
                return cached.key;
            }
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            OffsetDateTime keyExpiry = now.plus(DELEGATION_KEY_LIFETIME);
            UserDelegationKey newKey = blobServiceClient.getUserDelegationKey(now, keyExpiry);
            cachedDelegationKey.set(new CachedDelegationKey(newKey, keyExpiry));
            log.debug("Refreshed user delegation key, valid until {}", keyExpiry);
            return newKey;
        }
    }

    @NotNull
    static String getEndpointUrl(String accountName, String customBlobEndpoint) {
        if (StringUtils.isNotBlank(customBlobEndpoint)) {
            if (!customBlobEndpoint.startsWith("http://") && !customBlobEndpoint.startsWith("https://")) {
                return "https://" + customBlobEndpoint;
            }
            if (customBlobEndpoint.startsWith("http://")) {
                log.warn("Custom blob endpoint uses cleartext HTTP: {}", customBlobEndpoint);
            }
            return customBlobEndpoint;
        }
        return String.format("https://%s.blob.%s", accountName, DEFAULT_ENDPOINT_SUFFIX);
    }

    /** Holds a {@link UserDelegationKey} alongside the expiry we requested it with. */
    static final class CachedDelegationKey {
        final UserDelegationKey key;
        final OffsetDateTime expiry;

        CachedDelegationKey(UserDelegationKey key, OffsetDateTime expiry) {
            this.key = key;
            this.expiry = expiry;
        }
    }

    // -------------------------------------------------------------------------
    // Builder
    // -------------------------------------------------------------------------

    static class Builder {
        private final String containerName;
        private String azureConnectionString;
        private String accountName;
        private String blobEndpoint;
        private String sasToken;
        private String accountKey;
        private String tenantId;
        private String clientId;
        private String clientSecret;
        private String proxyHost;
        private String proxyPort;
        private RequestRetryOptions retryOptions;

        private Builder(String containerName) {
            this.containerName = containerName;
        }

        public static Builder builder(String containerName) {
            return new Builder(containerName);
        }

        public Builder withAzureConnectionString(String azureConnectionString) {
            this.azureConnectionString = azureConnectionString;
            return this;
        }

        public Builder withAccountName(String accountName) {
            this.accountName = accountName;
            return this;
        }

        public Builder withBlobEndpoint(String blobEndpoint) {
            this.blobEndpoint = blobEndpoint;
            return this;
        }

        public Builder withSasToken(String sasToken) {
            this.sasToken = sasToken;
            return this;
        }

        public Builder withAccountKey(String accountKey) {
            this.accountKey = accountKey;
            return this;
        }

        public Builder withTenantId(String tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder withClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder withClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder withProxyHost(String proxyHost) {
            this.proxyHost = proxyHost;
            return this;
        }

        public Builder withProxyPort(String proxyPort) {
            this.proxyPort = proxyPort;
            return this;
        }

        public Builder withRetryOptions(RequestRetryOptions retryOptions) {
            this.retryOptions = retryOptions;
            return this;
        }

        public Builder initializeWithProperties(Properties properties) {
            withAzureConnectionString(properties.getProperty(AzureConstantsV12.AZURE_CONNECTION_STRING, ""));
            withAccountName(properties.getProperty(AzureConstantsV12.AZURE_STORAGE_ACCOUNT_NAME, ""));
            withBlobEndpoint(properties.getProperty(AzureConstantsV12.AZURE_BLOB_ENDPOINT, ""));
            withSasToken(properties.getProperty(AzureConstantsV12.AZURE_SAS, ""));
            withAccountKey(properties.getProperty(AzureConstantsV12.AZURE_STORAGE_ACCOUNT_KEY, ""));
            withTenantId(properties.getProperty(AzureConstantsV12.AZURE_TENANT_ID, ""));
            withClientId(properties.getProperty(AzureConstantsV12.AZURE_CLIENT_ID, ""));
            withClientSecret(properties.getProperty(AzureConstantsV12.AZURE_CLIENT_SECRET, ""));
            withProxyHost(properties.getProperty(AzureConstantsV12.PROXY_HOST, ""));
            withProxyPort(properties.getProperty(AzureConstantsV12.PROXY_PORT, ""));
            return this;
        }

        public AzureBlobContainerProviderV12 build() {
            HttpClient httpClient = new NettyAsyncHttpClientBuilder()
                    .proxy(UtilsV12.createProxyOptions(proxyHost, proxyPort))
                    .build();
            if (isServicePrincipal()) {
                ClientSecretCredential credential = new ClientSecretCredentialBuilder()
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .tenantId(tenantId)
                        .build();
                return new ServicePrincipalProvider(containerName, httpClient, retryOptions,
                        accountName, blobEndpoint, credential);
            }
            return new SharedKeyProvider(containerName, httpClient, retryOptions,
                    azureConnectionString, accountName, blobEndpoint, sasToken, accountKey);
        }

        private boolean isServicePrincipal() {
            return StringUtils.isBlank(azureConnectionString) &&
                    StringUtils.isNoneBlank(accountName, tenantId, clientId, clientSecret);
        }
    }
}
