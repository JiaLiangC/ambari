/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ambari.server.registry.json;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Set;

import org.apache.ambari.server.AmbariException;
import org.apache.commons.lang3.StringUtils;

/** Bounded URI reader shared by JSON registry metadata consumers. */
final class RegistryUriLoader {
  private static final int CONNECT_TIMEOUT_MILLIS = 30_000;
  private static final int READ_TIMEOUT_MILLIS = 60_000;
  private static final Set<String> SUPPORTED_SCHEMES = Set.of("file", "http", "https");

  private RegistryUriLoader() {
  }

  static URI parseAbsolute(String value, String description) throws AmbariException {
    if (StringUtils.isBlank(value)) {
      throw new AmbariException(description + " must not be empty");
    }
    try {
      URI uri = new URI(value).normalize();
      String scheme = StringUtils.lowerCase(uri.getScheme(), Locale.ROOT);
      if (!uri.isAbsolute() || !SUPPORTED_SCHEMES.contains(scheme)) {
        throw new AmbariException("Unsupported " + description + " scheme: " + uri.getScheme());
      }
      if (uri.getRawUserInfo() != null) {
        throw new AmbariException(description + " must not contain user information");
      }
      if (uri.getRawFragment() != null) {
        throw new AmbariException(description + " must not contain a fragment");
      }
      if (("http".equals(scheme) || "https".equals(scheme))
          && StringUtils.isBlank(uri.getHost())) {
        throw new AmbariException(description + " must contain a host");
      }
      if ("file".equals(scheme) && !StringUtils.isBlank(uri.getHost())
          && !"localhost".equalsIgnoreCase(uri.getHost())) {
        throw new AmbariException(description + " must not reference a remote file host");
      }
      return uri;
    } catch (URISyntaxException e) {
      throw new AmbariException("Invalid " + description, e);
    }
  }

  static URI resolve(URI baseUri, String value, String description) throws AmbariException {
    if (StringUtils.isBlank(value)) {
      throw new AmbariException(description + " must not be empty");
    }
    try {
      URI resolved = baseUri.resolve(".").resolve(new URI(value)).normalize();
      return parseAbsolute(resolved.toString(), description);
    } catch (URISyntaxException e) {
      throw new AmbariException("Invalid " + description, e);
    }
  }

  static String readUtf8(URI uri, long maximumBytes, String description) throws AmbariException {
    try {
      URLConnection connection = uri.toURL().openConnection();
      connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
      connection.setReadTimeout(READ_TIMEOUT_MILLIS);
      connection.setUseCaches(false);
      long declaredLength = connection.getContentLengthLong();
      if (declaredLength > maximumBytes) {
        throw tooLarge(description, maximumBytes);
      }

      try (InputStream input = connection.getInputStream();
          ByteArrayOutputStream output = new ByteArrayOutputStream()) {
        byte[] buffer = new byte[8192];
        long total = 0;
        int count;
        while ((count = input.read(buffer)) != -1) {
          total += count;
          if (total > maximumBytes) {
            throw tooLarge(description, maximumBytes);
          }
          output.write(buffer, 0, count);
        }
        return output.toString(StandardCharsets.UTF_8);
      }
    } catch (IOException e) {
      throw new AmbariException("Unable to read " + description, e);
    }
  }

  private static AmbariException tooLarge(String description, long maximumBytes) {
    return new AmbariException(description + " exceeds the maximum size of " + maximumBytes + " bytes");
  }
}
