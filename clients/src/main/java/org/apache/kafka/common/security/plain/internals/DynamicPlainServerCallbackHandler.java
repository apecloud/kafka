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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;

/**
 * Dynamic PLAIN SASL callback handler with separated static and dynamic
 * credentials.
 * 
 * Architecture:
 * - Static credentials: Loaded from JAAS config at startup (admin, system
 * accounts)
 * - Dynamic credentials: Loaded from a single file, support hot-reload (regular
 * users)
 * 
 * Features:
 * - Thread-safe credential cache with read-write locks
 * - MD5 password hashing for security
 * - Automatic file reload when modified
 * - Zero-downtime credential updates
 * - Kubernetes Secret/ConfigMap compatible
 * 
 * Configuration:
 * 
 * 1. System property or environment variable for dynamic credentials:
 * -Dkafka.dynamic.credential.file=/path/to/users.properties
 * or KAFKA_DYNAMIC_CREDENTIAL_FILE=/path/to/users.properties
 * 
 * 2. server.properties:
 * listener.name.sasl_ssl.plain.sasl.server.callback.handler.class=org.apache.kafka.common.security.plain.internals.DynamicPlainServerCallbackHandler
 * 
 * 3. Static JAAS config (kafka_jaas.conf) - system managed, not exposed to
 * users:
 * KafkaServer {
 * org.apache.kafka.common.security.plain.PlainLoginModule required
 * username="admin"
 * password="21232f297a57a5a743894a0e4a801fc3"
 * user_admin="21232f297a57a5a743894a0e4a801fc3";
 * };
 * 
 * 4. Dynamic credential file - user managed, hot-reloadable:
 * File: /path/to/users.properties
 * Format: username=md5hash (one per line)
 * 
 * producer=5f4dcc3b5aa765d61d8327deb882cf99
 * consumer=098f6bcd4621d373cade4e832627b4f6
 * app-user=5ebe2294ecd0e0f08eab7690d2a6ee69
 * 
 * Generate MD5 hash: echo -n "your_password" | md5sum
 */
public class DynamicPlainServerCallbackHandler implements AuthenticateCallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(DynamicPlainServerCallbackHandler.class);
    private static final String JAAS_USER_PREFIX = "user_";
    private static final String CREDENTIAL_FILE_PROPERTY = "kafka.dynamic.credential.file";
    private static final String CREDENTIAL_FILE_ENV = "KAFKA_DYNAMIC_CREDENTIAL_FILE";

    private final Map<String, String> staticCredentials = new ConcurrentHashMap<>();
    private final Map<String, String> dynamicCredentials = new ConcurrentHashMap<>();
    private final ReadWriteLock lock = new ReentrantReadWriteLock();

    private String credentialFile;
    private volatile long lastModifiedTime = 0L;
    private volatile boolean initialized = false;

    @Override
    public void configure(Map<String, ?> configs, String mechanism, List<AppConfigurationEntry> jaasConfigEntries) {
        loadStaticCredentialsFromJaas(jaasConfigEntries);

        credentialFile = System.getProperty(CREDENTIAL_FILE_PROPERTY);
        if (credentialFile == null) {
            credentialFile = System.getenv(CREDENTIAL_FILE_ENV);
        }

        if (credentialFile != null) {
            File file = new File(credentialFile);
            if (file.exists() && file.isFile()) {
                loadDynamicCredentials();
                log.info("Monitoring credential file: {} ({} users loaded)",
                        credentialFile, dynamicCredentials.size());
            } else {
                log.warn("Credential file does not exist or is not a file: {}", credentialFile);
            }
        } else {
            log.info("No credential file configured ({}), only static JAAS credentials available",
                    CREDENTIAL_FILE_PROPERTY);
        }

        this.initialized = true;
        log.info("DynamicPlainServerCallbackHandler configured with mechanism: {} " +
                "(static users: {}, dynamic users: {})",
                mechanism, staticCredentials.size(), dynamicCredentials.size());
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
     * Authenticate user with password using MD5 hash comparison.
     * 
     * Authentication flow:
     * 1. Check if dynamic credential file has been modified and reload if needed
     * 2. Check static credentials first (from JAAS)
     * 3. If not found, check dynamic credentials (from file)
     * 4. Compute MD5 hash of provided password and compare
     * 
     * Client sends plaintext password, server compares MD5 hash with stored hash.
     */
    protected boolean authenticate(String username, char[] password) throws IOException {
        if (username == null) {
            return false;
        }

        checkAndReloadDynamicCredentials();

        lock.readLock().lock();
        try {
            String cachedPassword = staticCredentials.get(username);
            if (cachedPassword != null) {
                return Utils.isEqualConstantTime(password, cachedPassword.toCharArray());
            }

            String cachedPasswordHash = dynamicCredentials.get(username);
            if (cachedPasswordHash == null) {
                log.debug("User '{}' not found in credentials", username);
                return false;
            }

            String passwordHash = computeMD5Hash(password);
            if (passwordHash == null) {
                log.error("Failed to compute MD5 hash for user: {}", username);
                return false;
            }

            return Utils.isEqualConstantTime(passwordHash.toCharArray(),
                    cachedPasswordHash.toCharArray());

        } finally {
            lock.readLock().unlock();
        }
    }

    private String computeMD5Hash(char[] password) {
        byte[] passwordBytes = null;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            passwordBytes = charArrayToByteArray(password);
            byte[] hashBytes = md.digest(passwordBytes);

            StringBuilder sb = new StringBuilder(32);
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error("MD5 algorithm not available", e);
            return null;
        } finally {
            if (passwordBytes != null) {
                java.util.Arrays.fill(passwordBytes, (byte) 0);
            }
        }
    }

    private byte[] charArrayToByteArray(char[] chars) {
        java.nio.CharBuffer charBuffer = java.nio.CharBuffer.wrap(chars);
        java.nio.ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
        byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes);
        byteBuffer.clear();
        return bytes;
    }

    /**
     * Load static credentials from JAAS configuration.
     * These credentials are read-only and only loaded once at startup.
     * Includes admin and system accounts that should not be exposed to users.
     */
    private void loadStaticCredentialsFromJaas(List<AppConfigurationEntry> jaasConfigEntries) {
        if (jaasConfigEntries == null || jaasConfigEntries.isEmpty()) {
            log.warn("No JAAS configuration entries provided");
            return;
        }

        for (AppConfigurationEntry entry : jaasConfigEntries) {
            Map<String, ?> options = entry.getOptions();
            for (Map.Entry<String, ?> option : options.entrySet()) {
                String key = option.getKey();
                if (key.startsWith(JAAS_USER_PREFIX)) {
                    String username = key.substring(JAAS_USER_PREFIX.length());
                    String passwordHash = (String) option.getValue();
                    staticCredentials.put(username, passwordHash);
                    log.debug("Loaded static credential for user: {}", username);
                }
            }
        }
        log.info("Loaded {} static users from JAAS configuration", staticCredentials.size());
    }

    /**
     * Load all dynamic credentials from file at startup.
     * File format: username=md5hash (one per line)
     * 
     * Example:
     * producer=5f4dcc3b5aa765d61d8327deb882cf99
     * consumer=098f6bcd4621d373cade4e832627b4f6
     * app-user=5ebe2294ecd0e0f08eab7690d2a6ee69
     */
    private void loadDynamicCredentials() {
        File file = new File(credentialFile);
        if (!file.exists() || !file.isFile()) {
            log.warn("Credential file does not exist: {}", credentialFile);
            return;
        }

        lock.writeLock().lock();
        try {
            dynamicCredentials.clear();

            List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
            long fileModTime = file.lastModified();

            for (String line : lines) {
                line = line.trim();

                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                int equalsIndex = line.indexOf('=');
                if (equalsIndex <= 0 || equalsIndex == line.length() - 1) {
                    log.warn("Invalid credential line format (expected username=hash): {}", line);
                    continue;
                }

                String username = line.substring(0, equalsIndex).trim();
                String passwordHash = line.substring(equalsIndex + 1).trim();

                dynamicCredentials.put(username, passwordHash.toLowerCase());
                log.debug("Loaded dynamic credential for user: {}", username);
            }

            this.lastModifiedTime = fileModTime;
            log.info("Loaded {} dynamic users from credential file", dynamicCredentials.size());

        } catch (IOException e) {
            log.error("Failed to load credential file: {}", credentialFile, e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Check if credential file has been modified and reload if needed.
     * This method is called before each authentication attempt.
     * 
     * Performance optimization: Only checks file mtime, only reloads if changed.
     */
    private void checkAndReloadDynamicCredentials() {
        if (credentialFile == null) {
            return;
        }

        File file = new File(credentialFile);
        if (!file.exists()) {
            return;
        }

        long currentModTime = file.lastModified();

        if (currentModTime == lastModifiedTime) {
            return;
        }

        lock.writeLock().lock();
        try {
            currentModTime = file.lastModified();
            if (currentModTime == lastModifiedTime) {
                return;
            }

            log.info("Credential file modified, reloading: {}", credentialFile);

            dynamicCredentials.clear();

            List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);

            for (String line : lines) {
                line = line.trim();

                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                int equalsIndex = line.indexOf('=');
                if (equalsIndex <= 0 || equalsIndex == line.length() - 1) {
                    log.warn("Invalid credential line format (expected username=hash): {}", line);
                    continue;
                }

                String username = line.substring(0, equalsIndex).trim();
                String passwordHash = line.substring(equalsIndex + 1).trim();

                dynamicCredentials.put(username, passwordHash.toLowerCase());
            }

            this.lastModifiedTime = currentModTime;
            log.info("Successfully reloaded {} dynamic users from credential file", dynamicCredentials.size());

        } catch (IOException e) {
            log.error("Failed to reload credential file: {}", credentialFile, e);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Get total number of cached credentials (static + dynamic).
     * Useful for monitoring and debugging.
     */
    public int getCredentialCacheSize() {
        lock.readLock().lock();
        try {
            return staticCredentials.size() + dynamicCredentials.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Get number of static credentials.
     */
    public int getStaticCredentialCount() {
        return staticCredentials.size();
    }

    /**
     * Get number of dynamic credentials.
     */
    public int getDynamicCredentialCount() {
        lock.readLock().lock();
        try {
            return dynamicCredentials.size();
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void close() throws KafkaException {
        lock.writeLock().lock();
        try {
            staticCredentials.clear();
            dynamicCredentials.clear();
            log.info("DynamicPlainServerCallbackHandler closed");
        } finally {
            lock.writeLock().unlock();
        }
    }
}
