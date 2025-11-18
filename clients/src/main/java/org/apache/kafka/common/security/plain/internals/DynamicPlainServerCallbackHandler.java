/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.kafka.common.security.plain.internals;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.plain.PlainAuthenticateCallback;
import org.apache.kafka.common.utils.Utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

/**
 * Dynamic PLAIN SASL callback handler that supports runtime credential updates.
 * This handler provides a unified approach to dynamic SASL updates across
 * different Kafka versions.
 * 
 * Features:
 * - Thread-safe credential cache with read-write locks
 * - Support for dynamic credential updates without broker restart
 * - Compatible with both pre-3.9 and 3.9+ KRaft versions
 * - Custom business logic for authentication validation
 * 
 * Configuration example:
 * listener.name.sasl_ssl.plain.sasl.server.callback.handler.class=org.apache.kafka.common.security.plain.internals.DynamicPlainServerCallbackHandler
 */
public class DynamicPlainServerCallbackHandler implements AuthenticateCallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(DynamicPlainServerCallbackHandler.class);
    private static final String JAAS_USER_PREFIX = "user_";
    private static final String JAAS_CONFIG_PROPERTY = "java.security.auth.login.config";

    // Thread-safe credential cache
    private final Map<String, String> credentialCache = new ConcurrentHashMap<>();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    // JAAS file tracking
    private String jaasConfigFilePath;
    private volatile long lastModifiedTime = 0L;

    private List<AppConfigurationEntry> jaasConfigEntries;
    private volatile boolean initialized = false;

    @Override
    public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        this.jaasConfigEntries = jaasConfigEntries;

        // Get JAAS file path from system property
        this.jaasConfigFilePath = System.getProperty(JAAS_CONFIG_PROPERTY);

        if (jaasConfigFilePath != null) {
            File jaasFile = new File(jaasConfigFilePath);
            if (jaasFile.exists()) {
                this.lastModifiedTime = jaasFile.lastModified();
                log.info("Monitoring JAAS config file: {} (last modified: {})",
                        jaasConfigFilePath, lastModifiedTime);
            } else {
                log.warn("JAAS config file does not exist: {}", jaasConfigFilePath);
            }
        } else {
            log.info("No JAAS config file specified via {}, dynamic reload disabled",
                    JAAS_CONFIG_PROPERTY);
        }

        // Load initial credentials from JAAS configuration
        loadCredentialsFromJaas();
        this.initialized = true;
        log.info("DynamicPlainServerCallbackHandler configured with mechanism: {}", mechanism);
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        if (!initialized) {
            throw new IOException("CallbackHandler not initialized");
        }

        String username = null;
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                username = ((NameCallback) callback).getDefaultName();
            } else if (callback instanceof PlainAuthenticateCallback) {
                PlainAuthenticateCallback plainCallback = (PlainAuthenticateCallback) callback;
                boolean authenticated = authenticate(username, plainCallback.password());
                plainCallback.authenticated(authenticated);

                if (authenticated) {
                    log.debug("User '{}' authenticated successfully", username);
                } else {
                    log.warn("Authentication failed for user '{}'", username);
                }
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    /**
     * Authenticate user with password
     * Override this method to add custom business logic
     * 
     * This method checks if the JAAS file has been modified before each
     * authentication.
     * If modified, it reloads the credentials from the file into cache.
     * 
     */
    protected boolean authenticate(String username, char[] password) throws IOException {
        if (username == null) {
            return false;
        }

        checkAndReloadJaasFile();

        lock.readLock().lock();
        try {
            String cachedPassword = credentialCache.get(username);
            return cachedPassword != null
                    && Utils.isEqualConstantTime(password, cachedPassword.toCharArray());

        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Check if JAAS file has been modified and reload if needed
     * 
     * This is a lightweight operation that only checks file modification time.
     * If the file has been modified, it triggers a reload of credentials.
     */
    private void checkAndReloadJaasFile() {
        if (jaasConfigFilePath == null) {
            return;
        }

        File jaasFile = new File(jaasConfigFilePath);
        if (!jaasFile.exists()) {
            return;
        }

        long currentModifiedTime = jaasFile.lastModified();

        if (currentModifiedTime == lastModifiedTime) {
            return;
        }

        lock.writeLock().lock();
        try {
            // Double-check
            currentModifiedTime = jaasFile.lastModified();
            if (currentModifiedTime == lastModifiedTime) {
                return;
            }

            log.info("JAAS config file modified, reloading credentials from: {}", jaasConfigFilePath);

            // Force reload of JAAS configuration
            Configuration.setConfiguration(null);
            Configuration config = Configuration.getConfiguration();

            // Get updated configuration
            AppConfigurationEntry[] newEntries = config.getAppConfigurationEntry("KafkaServer");
            if (newEntries != null && newEntries.length > 0) {
                this.jaasConfigEntries = java.util.Arrays.asList(newEntries);
            }

            loadCredentialsFromJaas();

            this.lastModifiedTime = currentModifiedTime;

            log.info("Successfully reloaded {} users from JAAS config file", credentialCache.size());

        } catch (Exception e) {
            log.error("Failed to reload JAAS configuration from file: " + jaasConfigFilePath, e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Custom business logic for additional authentication checks
     * Override this method to implement your specific requirements
     * 
     * @param username the authenticated username
     * @return true if custom checks pass, false otherwise
     */
    protected boolean customAuthenticationCheck(String username) {
        // Example: Add your custom business logic here
        // - Check user against external database
        // - Validate user permissions
        // - Check account status (active/disabled)
        // - Apply rate limiting
        // - Log authentication events

        // Default implementation: allow all authenticated users
        return true;
    }

    /**
     * Load credentials from JAAS configuration into cache
     * This method should be called with write lock held
     */
    private void loadCredentialsFromJaas() {
        credentialCache.clear();

        if (jaasConfigEntries != null) {
            for (AppConfigurationEntry entry : jaasConfigEntries) {
                Map<String, ?> options = entry.getOptions();
                for (Map.Entry<String, ?> option : options.entrySet()) {
                    String key = option.getKey();
                    if (key.startsWith(JAAS_USER_PREFIX)) {
                        String username = key.substring(JAAS_USER_PREFIX.length());
                        String password = (String) option.getValue();
                        credentialCache.put(username, password);
                    }
                }
            }
            log.debug("Loaded {} users from JAAS configuration", credentialCache.size());
        }
    }

    /**
     * Get current credential cache size (for monitoring)
     */
    public int getCredentialCacheSize() {
        lock.readLock().lock();
        try {
            return credentialCache.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void close() throws KafkaException {
        lock.writeLock().lock();
        try {
            credentialCache.clear();
            log.info("DynamicPlainServerCallbackHandler closed");
        } finally {
            lock.writeLock().unlock();
        }
    }
}
