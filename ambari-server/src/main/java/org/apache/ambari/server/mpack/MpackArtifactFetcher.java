/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ambari.server.mpack;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.configuration.Configuration;
import org.apache.ambari.server.security.credential.Credential;
import org.apache.ambari.server.security.encryption.CredentialStoreService;
import org.apache.commons.lang3.StringUtils;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Applies source policy and resource limits while fetching package artifacts. */
final class MpackArtifactFetcher {
  private static final int CONNECT_TIMEOUT_MILLIS = 30_000;
  private static final int READ_TIMEOUT_MILLIS = 60_000;
  private static final long MAX_POLICY_BYTES = 1024L * 1024L;
  private static final Set<String> SUPPORTED_URI_SCHEMES = Set.of("file", "http", "https");

  URI parse(String value) {
    if (StringUtils.isBlank(value)) {
      throw new IllegalArgumentException("Mpack URI must not be empty");
    }
    try {
      URI uri = new URI(value).normalize();
      String scheme = StringUtils.lowerCase(uri.getScheme());
      if (!uri.isAbsolute() || !SUPPORTED_URI_SCHEMES.contains(scheme)) {
        throw new IllegalArgumentException("Unsupported mpack URI scheme: " + uri.getScheme());
      }
      if (uri.getRawUserInfo() != null) {
        throw new IllegalArgumentException("Mpack URI must not contain user information");
      }
      if (uri.getRawQuery() != null) {
        throw new IllegalArgumentException("Mpack URLs use configured credential references, not query parameters");
      }
      if (uri.getRawFragment() != null) {
        throw new IllegalArgumentException("Mpack URI must not contain a fragment");
      }
      if (("http".equals(scheme) || "https".equals(scheme)) && StringUtils.isBlank(uri.getHost())) {
        throw new IllegalArgumentException("Mpack URI must contain a host");
      }
      if ("file".equals(scheme) && StringUtils.isNotBlank(uri.getHost())
          && !"localhost".equalsIgnoreCase(uri.getHost())) {
        throw new IllegalArgumentException("Mpack URI must not reference a remote file host");
      }
      return uri;
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid mpack URI", e);
    }
  }

  URI resolve(URI metadataUri, String definition) {
    URI resolved = metadataUri.resolve(".").resolve(definition).normalize();
    if (!StringUtils.equalsIgnoreCase(metadataUri.getScheme(), resolved.getScheme())) {
      throw new IllegalArgumentException("Mpack definition must use the metadata URI scheme");
    }
    return resolved;
  }

  void download(URI source, Path target, long maximumBytes, Configuration configuration,
      CredentialStoreService credentials) throws IOException {
    URLConnection connection = source.toURL().openConnection();
    HttpURLConnection http = connection instanceof HttpURLConnection
        ? (HttpURLConnection) connection : null;
    if (http != null) {
      http.setInstanceFollowRedirects(false);
      applyPolicy(source, http, configuration, credentials);
    }
    connection.setUseCaches(false);
    connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
    connection.setReadTimeout(READ_TIMEOUT_MILLIS);
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(120);
    try {
      if (http != null && http.getResponseCode() != HttpURLConnection.HTTP_OK) {
        throw new IOException("Artifact source did not return HTTP 200; redirects are not accepted");
      }
      long declaredLength = connection.getContentLengthLong();
      if (declaredLength > maximumBytes) {
        throw new IOException("Remote content exceeds the allowed size");
      }
      Files.createDirectories(target.getParent());
      try (InputStream input = new BufferedInputStream(connection.getInputStream());
          OutputStream output = new BufferedOutputStream(Files.newOutputStream(target,
              StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
        byte[] buffer = new byte[65536];
        long total = 0;
        int count;
        while ((count = input.read(buffer)) != -1) {
          total += count;
          if (total > maximumBytes || System.nanoTime() > deadline) {
            throw new IOException("Artifact transfer exceeded size or duration limit");
          }
          output.write(buffer, 0, count);
        }
        if (declaredLength >= 0 && declaredLength != total) {
          throw new IOException("Artifact source returned incomplete content");
        }
      }
    } finally {
      if (http != null) {
        http.disconnect();
      }
    }
  }

  private void applyPolicy(URI source, HttpURLConnection connection, Configuration configuration,
      CredentialStoreService credentials) throws IOException {
    String policyFile = configuration == null ? null : configuration.getProperty("mpack.download.policy.file");
    if (StringUtils.isBlank(policyFile)) {
      throw new IOException("Network package imports require an administrator-configured artifact source policy");
    }
    Path policyPath = Paths.get(policyFile);
    if (!Files.isRegularFile(policyPath, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        || Files.size(policyPath) > MAX_POLICY_BYTES) {
      throw new IOException("Invalid artifact source policy file");
    }
    try {
      JsonObject policy = JsonParser.parseString(Files.readString(policyPath)).getAsJsonObject();
      String origin = source.getScheme().toLowerCase(Locale.ROOT) + "://"
          + source.getHost().toLowerCase(Locale.ROOT) + ":"
          + (source.getPort() < 0 ? ("https".equalsIgnoreCase(source.getScheme()) ? 443 : 80) : source.getPort());
      JsonObject sources = policy.getAsJsonObject("sources");
      JsonObject allowed = sources == null ? null : sources.getAsJsonObject(origin);
      String prefix = allowed == null || !allowed.has("pathPrefix")
          ? null : allowed.get("pathPrefix").getAsString();
      if (prefix == null || !prefix.startsWith("/") || !prefix.endsWith("/")
          || !source.normalize().getPath().startsWith(prefix) || source.getRawPath().contains("%")) {
        throw new IOException("Artifact URL is outside the approved origin and path");
      }
      if (allowed.has("credential")) {
        if (!"https".equalsIgnoreCase(source.getScheme()) || credentials == null) {
          throw new IOException("Private artifact sources require HTTPS and a credential store");
        }
        JsonObject reference = allowed.getAsJsonObject("credential");
        Credential credential = credentials.getCredential(
            reference.get("cluster").getAsString(), reference.get("alias").getAsString());
        char[] token = MpackSecrets.credentialKey(credential);
        if (token == null || token.length == 0 || token.length > 8192) {
          throw new IOException("Invalid artifact bearer credential");
        }
        for (char value : token) {
          if (value < 33 || value > 126) {
            throw new IOException("Invalid artifact bearer credential");
          }
        }
        connection.setRequestProperty("Authorization", "Bearer " + new String(token));
      }
    } catch (AmbariException | RuntimeException invalidPolicy) {
      throw new IOException("Artifact source policy or credential resolution failed", invalidPolicy);
    }
  }
}
