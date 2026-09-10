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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;

import org.apache.ambari.server.configuration.Configuration;
import org.apache.ambari.server.controller.MpackRequest;
import org.apache.ambari.server.controller.MpackResponse;
import org.apache.ambari.server.controller.spi.ResourceAlreadyExistsException;
import org.apache.ambari.server.orm.dao.MpackDAO;
import org.apache.ambari.server.orm.dao.StackDAO;
import org.apache.ambari.server.orm.entities.MpackEntity;
import org.apache.ambari.server.orm.entities.StackEntity;
import org.apache.ambari.server.stack.RepoUtil;
import org.apache.ambari.server.state.Module;
import org.apache.ambari.server.state.ModuleComponent;
import org.apache.ambari.server.state.ModuleDependency;
import org.apache.ambari.server.state.Mpack;
import org.apache.ambari.server.state.MpackOsSpecific;
import org.apache.ambari.server.state.RepositoryInfo;
import org.apache.ambari.server.state.stack.RepositoryXml;
import org.apache.ambari.server.state.stack.StackMetainfoXml;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;
import com.google.inject.assistedinject.AssistedInject;

/**
 * Manages mpack metadata, registration and its compatibility projection into
 * the Stack resource tree.
 */
public class MpackManager {
  @com.google.inject.Inject
  private org.apache.ambari.server.security.encryption.CredentialStoreService artifactCredentials;

  private static final String MPACK_METADATA = "mpack.json";
  private static final String MPACK_TAR_LOCATION = "staging";
  private static final String MODULE_ARCHIVES_DIRECTORY = "modules";
  private static final String MODULES_DIRECTORY = "services";
  private static final String MIN_JDK_PROPERTY = "min-jdk";
  private static final String MAX_JDK_PROPERTY = "max-jdk";
  private static final String DEFAULT_JDK_VALUE = "1.8";
  private static final int CONNECT_TIMEOUT_MILLIS = 30_000;
  private static final int READ_TIMEOUT_MILLIS = 60_000;
  private static final long MAX_METADATA_BYTES = 1024L * 1024L;
  private static final long MAX_ARCHIVE_BYTES = 512L * 1024L * 1024L;
  private static final long MAX_EXPANDED_BYTES = 2L * 1024L * 1024L * 1024L;
  private static final int MAX_ARCHIVE_ENTRIES = 100_000;
  private static final Pattern IDENTIFIER_PATTERN = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]*");
  private static final Set<String> SUPPORTED_URI_SCHEMES = Set.of("file", "http", "https");
  private static final Logger LOG = LoggerFactory.getLogger(MpackManager.class);

  protected final ConcurrentMap<Long, Mpack> mpackMap = new ConcurrentHashMap<>();
  private final File mpackStaging;
  private final MpackDAO mpackDAO;
  private final StackDAO stackDAO;
  private final File stackRoot;
  private final Object registrationLock = new Object();
  @Inject
  private Configuration configuration;
  private static final String REGISTRATION_PENDING = ".ambari-registration-pending";
  private static final String DELETION_PENDING = ".ambari-deletion-pending";

  @AssistedInject
  public MpackManager(
      @Assisted("mpacksv2Staging") File mpacksStagingLocation,
      @Assisted("stackRoot") File stackRootDir,
      MpackDAO mpackDAOObj,
      StackDAO stackDAOObj) {
    mpackStaging = mpacksStagingLocation;
    mpackDAO = mpackDAOObj;
    stackRoot = stackRootDir;
    stackDAO = stackDAOObj;
    parseMpackDirectories();
  }

  /**
   * Loads registered mpacks from disk during server startup. A malformed
   * package is isolated so that other packages remain available.
   */
  private void parseMpackDirectories() {
    File[] mpackDirectories = mpackStaging.listFiles();
    if (mpackDirectories == null) {
      return;
    }

    for (File mpackDirectory : mpackDirectories) {
      if (!mpackDirectory.isDirectory() || MPACK_TAR_LOCATION.equals(mpackDirectory.getName())) {
        continue;
      }
      File[] versionDirectories = mpackDirectory.listFiles();
      if (versionDirectories == null) {
        continue;
      }

      for (File versionDirectory : versionDirectories) {
        if (!versionDirectory.isDirectory()) {
          continue;
        }
        String mpackName = mpackDirectory.getName();
        String mpackVersion = versionDirectory.getName();
        try {
          List<MpackEntity> entities = mpackDAO.findByNameVersion(mpackName, mpackVersion);
          if (entities.isEmpty()) {
            quarantineIncompleteRegistration(versionDirectory.toPath());
            continue;
          }
          Mpack existingMpack = readMpackMetadata(versionDirectory.toPath().resolve(MPACK_METADATA));
          validateMpackMetadata(existingMpack);
          loadRepositoryMetadata(existingMpack, versionDirectory.toPath());
          if (!validateMpackInfo(mpackName, mpackVersion,
              existingMpack.getName(), existingMpack.getVersion())) {
            LOG.error("Ignoring mpack directory {} because its metadata identity does not match", versionDirectory);
            continue;
          }
          MpackEntity entity = entities.get(0);
          verifyCatalogMetadata(entity, existingMpack);
          if (!java.util.Objects.equals(entity.getContentDigest(), existingMpack.getPackageDigest())) {
            throw new IOException("Package digest differs from catalog authority");
          }
          existingMpack.setResourceId(entity.getId());
          existingMpack.setMpackUri(entity.getMpackUri());
          existingMpack.setRegistryId(entity.getRegistryId());
          // A surviving DB row means the deletion transaction did not commit.
          Files.deleteIfExists(versionDirectory.toPath().resolve(DELETION_PENDING));
          if (Files.exists(versionDirectory.toPath().resolve(REGISTRATION_PENDING))) {
            StackEntity stack = stackDAO.find(existingMpack.getStackName(), mpackVersion);
            if (stack == null && !existingMpack.getStackName().equals(mpackName)) {
              stack = stackDAO.find(mpackName, mpackVersion);
            }
            if (stack == null) {
              populateStackDB(existingMpack);
            } else if (!entity.getId().equals(stack.getMpackId())) {
              throw new IOException("Stack identity belongs to another package");
            }
            ensureStackProjection(existingMpack, versionDirectory.toPath());
            Files.delete(versionDirectory.toPath().resolve(REGISTRATION_PENDING));
          }
          ensureDefaultRepository(existingMpack);
          ensureStackProjection(existingMpack, versionDirectory.toPath());
          mpackMap.put(entity.getId(), existingMpack);
        } catch (IOException | ResourceAlreadyExistsException | RuntimeException e) {
          LOG.error("Unable to load registered mpack {}-{} from {}", mpackName, mpackVersion,
              versionDirectory, e);
        }
      }
    }
  }

  public Map<Long, Mpack> getMpackMap() {
    return Collections.unmodifiableMap(mpackMap);
  }

  public void validateUpgrade(Long previousId, Long candidateId, String service) throws IOException {
    synchronized (registrationLock) {
      validateIdentifier(service, "service");
      Mpack previous = mpackMap.get(previousId);
      Mpack candidate = mpackMap.get(candidateId);
      if (previous == null || candidate == null || previous.getPackageDigest() == null || candidate.getPackageDigest() == null
          || !previous.getName().equals(candidate.getName())) {
        throw new IOException("Artifact update requires two available authored packages");
      }
      try {
        com.google.gson.JsonObject oldDescriptor = MpackConfiguration.read(finalMpackDirectory(previous)
            .resolve("services").resolve(service).resolve("package/manifest-service.json"));
        com.google.gson.JsonObject newDescriptor = MpackConfiguration.read(finalMpackDirectory(candidate)
            .resolve("services").resolve(service).resolve("package/manifest-service.json"));
        if (!previous.getPackageDigest().equals(oldDescriptor.getAsJsonObject("package").get("digest").getAsString())
            || !candidate.getPackageDigest().equals(newDescriptor.getAsJsonObject("package").get("digest").getAsString())
            || !previous.getName().equals(oldDescriptor.getAsJsonObject("package").get("name").getAsString())
            || !candidate.getName().equals(newDescriptor.getAsJsonObject("package").get("name").getAsString())
            || !service.equals(oldDescriptor.getAsJsonObject("service").get("name").getAsString())
            || !service.equals(newDescriptor.getAsJsonObject("service").get("name").getAsString())) {
          throw new IOException("Package descriptor differs from catalog authority");
        }
        MpackUpgrade.validate(oldDescriptor, newDescriptor);
      } catch (RuntimeException invalid) {
        throw new IOException("Package artifact update metadata is invalid");
      }
    }
  }

  public void validateConfiguration(Long packageId, String service, String type, Map<String, String> properties)
      throws IOException {
    synchronized (registrationLock) {
      Mpack pack = mpackMap.get(packageId);
      if (pack == null) {
        throw new IOException("Selected package is not available");
      }
      if (pack.getPackageDigest() == null) {
        return;
      }
      validateIdentifier(service, "service");
      Path module = finalMpackDirectory(pack).resolve("services").resolve(service).resolve("package");
      try {
        MpackConfiguration.validate(module, pack.getPackageDigest(), service, type, properties);
      } catch (RuntimeException invalid) {
        throw new IOException("SCHEMA_INVALID: package configuration is invalid");
      }
    }
  }

  public void setMpackMap(Map<Long, Mpack> replacement) {
    mpackMap.clear();
    if (replacement != null) {
      mpackMap.putAll(replacement);
    }
  }

  /**
   * Registers an mpack using an isolated staging directory. Files are fully
   * prepared before they become visible at the final path.
   */
  public MpackResponse registerMpack(MpackRequest request)
      throws IOException, IllegalArgumentException, ResourceAlreadyExistsException {
    if (request == null) {
      throw new IllegalArgumentException("Mpack request must not be null");
    }
    return registerMpackPrepared(request);
  }

  private MpackResponse registerMpackPrepared(MpackRequest request)
      throws IOException, ResourceAlreadyExistsException {
    URI metadataUri = parseMpackUri(request.getMpackUri());
    Path stagingDirectory = mpackStaging.toPath().toAbsolutePath().normalize();
    Files.createDirectories(stagingDirectory.resolve(MPACK_TAR_LOCATION));
    Path requestDirectory = Files.createTempDirectory(stagingDirectory.resolve(MPACK_TAR_LOCATION),
        "register-");
    Path publishedDirectory = null;
    Path stackLink = null;
    Long mpackResourceId = null;
    boolean stackPersisted = false;

    try {
      Path metadataPath = requestDirectory.resolve(MPACK_METADATA);
      boolean transportArchive = metadataUri.getPath().endsWith(".mpack");
      if (transportArchive) {
        Path transport = requestDirectory.resolve("release.mpack");
        download(metadataUri, transport, MAX_ARCHIVE_BYTES + MAX_METADATA_BYTES + 65536);
        unpackRelease(transport, requestDirectory);
      } else {
        download(metadataUri, metadataPath, MAX_METADATA_BYTES);
      }
      Mpack mpack = readMpackMetadata(metadataPath);
      validateMpackMetadata(mpack);

      if (request.getRegistryId() != null) {
        if (!validateMpackInfo(request.getMpackName(), request.getMpackVersion(),
            mpack.getName(), mpack.getVersion())) {
          throw new IllegalArgumentException("Registry mpack identity does not match downloaded metadata");
        }
        mpack.setRegistryId(request.getRegistryId());
      }
      mpack.setMpackUri(metadataUri.toString());

      Path finalDirectory = finalMpackDirectory(mpack);
      if (transportArchive && "file".equalsIgnoreCase(metadataUri.getScheme())) {
        // Uploaded transports are temporary. Retain a resolvable verified catalog source.
        mpack.setMpackUri(finalDirectory.resolve(MPACK_METADATA).toUri().toString());
      }
      URI archiveUri = resolveDefinitionUri(metadataUri, mpack.getDefinition());
      Path archivePath = requestDirectory.resolve("mpack-definition.tar.gz");
      if (transportArchive) {
        Path bundledDefinition = requestDirectory.resolve(mpack.getDefinition());
        if (!Files.isRegularFile(bundledDefinition, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
          throw new IOException("Deployable release has no matching definition archive");
        }
        Files.move(bundledDefinition, archivePath);
      } else {
        download(archiveUri, archivePath, MAX_ARCHIVE_BYTES);
      }
      verifyAuthoringArchive(mpack, archivePath);
      Path preparedDirectory = prepareMpack(requestDirectory, archivePath, metadataPath, mpack);

      // Recovery evidence travels atomically with the prepared definition.
      // The existing mpacks row remains the only registration authority.
      try (FileOutputStream marker = new FileOutputStream(
          preparedDirectory.resolve(REGISTRATION_PENDING).toFile())) {
        marker.write("registration/v1\n".getBytes(StandardCharsets.UTF_8));
        marker.getFD().sync();
      }
      synchronized (registrationLock) {
        Mpack existing = reconcileOrRequireAvailable(mpack, finalDirectory);
        if (existing != null) {
          return new MpackResponse(existing);
        }
        try {
          Files.createDirectories(finalDirectory.getParent());
          moveDirectory(preparedDirectory, finalDirectory);
          publishedDirectory = finalDirectory;
          stackLink = createStackProjection(mpack, finalDirectory);
          mpackResourceId = populateDB(mpack);
          if (mpackResourceId == null) {
            throw duplicateMpack(mpack);
          }
          mpack.setResourceId(mpackResourceId);
          populateStackDB(mpack);
          stackPersisted = true;
          ensureDefaultRepository(mpack);
          Files.delete(finalDirectory.resolve(REGISTRATION_PENDING));
          mpackMap.put(mpackResourceId, mpack);
          return new MpackResponse(mpack);
        } catch (IOException | ResourceAlreadyExistsException | RuntimeException error) {
          rollbackRegistration(mpackResourceId, stackPersisted, stackLink, publishedDirectory);
          throw error;
        }
      }
    } finally {
      FileUtils.deleteQuietly(requestDirectory.toFile());
    }
  }

  private Mpack reconcileOrRequireAvailable(Mpack mpack, Path finalDirectory)
      throws ResourceAlreadyExistsException, IOException {
    List<MpackEntity> entities = mpackDAO.findByNameVersion(mpack.getName(), mpack.getVersion());
    if (!entities.isEmpty()) {
      MpackEntity entity = entities.get(0);
      if (mpack.getPackageDigest() == null || !mpack.getPackageDigest().equals(entity.getContentDigest())) {
        throw duplicateMpack(mpack);
      }
      Mpack existing = readMpackMetadata(finalDirectory.resolve(MPACK_METADATA));
      verifyCatalogMetadata(entity, existing);
      if (!mpack.getPackageDigest().equals(existing.getPackageDigest())
          || !mpack.getName().equals(existing.getName()) || !mpack.getVersion().equals(existing.getVersion())) {
        throw new IOException("Existing definition does not match catalog authority");
      }
      existing.setResourceId(entity.getId());
      existing.setMpackUri(entity.getMpackUri());
      existing.setRegistryId(entity.getRegistryId());
      StackEntity stack = stackDAO.find(existing.getStackName(), existing.getVersion());
      if (stack == null && !existing.getName().equals(existing.getStackName())) {
        stack = stackDAO.find(existing.getName(), existing.getVersion());
      }
      if (stack == null) {
        populateStackDB(existing);
      } else if (!entity.getId().equals(stack.getMpackId())) {
        throw new IOException("Stack identity belongs to another package");
      }
      ensureDefaultRepository(existing);
      ensureStackProjection(existing, finalDirectory);
      Files.deleteIfExists(finalDirectory.resolve(REGISTRATION_PENDING));
      Files.deleteIfExists(finalDirectory.resolve(DELETION_PENDING));
      mpackMap.put(entity.getId(), existing);
      return existing;
    }
    quarantineIncompleteRegistration(finalDirectory);
    if (stackDAO.find(mpack.getStackName(), mpack.getVersion()) != null
        || Files.exists(finalDirectory, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      throw duplicateMpack(mpack);
    }
    return null;
  }

  private ResourceAlreadyExistsException duplicateMpack(Mpack mpack) {
    return new ResourceAlreadyExistsException(
        "Mpack " + mpack.getName() + " version " + mpack.getVersion() + " already exists in server");
  }

  private void ensureDefaultRepository(Mpack mpack) {
    if (mpack.getPackageDigest() != null) {
      mpack.setRepositoryVersionId(mpackDAO.ensureDefaultRepository(mpack.getResourceId()));
    }
  }

  private URI parseMpackUri(String value) {
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
      if (("http".equals(scheme) || "https".equals(scheme))
          && StringUtils.isBlank(uri.getHost())) {
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

  private URI resolveDefinitionUri(URI metadataUri, String definition) {
    validateRelativeArchivePath(definition, "mpack definition");
    URI resolved = metadataUri.resolve(".").resolve(definition).normalize();
    if (!StringUtils.equalsIgnoreCase(metadataUri.getScheme(), resolved.getScheme())) {
      throw new IllegalArgumentException("Mpack definition must use the metadata URI scheme");
    }
    return resolved;
  }

  private void unpackRelease(Path transport, Path directory) throws IOException {
    Set<String> names = new HashSet<>();
    long total = 0;
    try (org.apache.commons.compress.archivers.tar.TarArchiveInputStream archive =
        new org.apache.commons.compress.archivers.tar.TarArchiveInputStream(
            new java.util.zip.GZIPInputStream(Files.newInputStream(transport)))) {
      org.apache.commons.compress.archivers.tar.TarArchiveEntry entry;
      while ((entry = archive.getNextTarEntry()) != null) {
        String name = entry.getName();
        if (!entry.isFile() || entry.isSymbolicLink() || entry.isLink() || entry.isSparse()
            || !name.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
            || !(name.equals(MPACK_METADATA) || name.endsWith(".tar.gz"))
            || !names.add(name) || names.size() > 2) {
          throw new IOException("Invalid deployable release inventory");
        }
        long limit = name.equals(MPACK_METADATA) ? MAX_METADATA_BYTES : MAX_ARCHIVE_BYTES;
        if (entry.getSize() < 0 || entry.getSize() > limit) {
          throw new IOException("Deployable release entry exceeds its limit");
        }
        try (OutputStream output = Files.newOutputStream(directory.resolve(name), StandardOpenOption.CREATE_NEW)) {
          long copied = copyLimited(archive, output, limit);
          if (copied != entry.getSize()) {
            throw new IOException("Truncated deployable release");
          }
          total += copied;
        }
      }
    }
    if (names.size() != 2 || !names.contains(MPACK_METADATA) || total > MAX_ARCHIVE_BYTES + MAX_METADATA_BYTES) {
      throw new IOException("Incomplete deployable release inventory");
    }
  }

  private void download(URI source, Path target, long maximumBytes) throws IOException {
    URLConnection connection = source.toURL().openConnection();
    java.net.HttpURLConnection http = connection instanceof java.net.HttpURLConnection
        ? (java.net.HttpURLConnection) connection : null;
    if (http != null) {
      http.setInstanceFollowRedirects(false);
      applyDownloadPolicy(source, http);
    }
    connection.setUseCaches(false);
    connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
    connection.setReadTimeout(READ_TIMEOUT_MILLIS);
    long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(120);
    try {
      if (http != null && http.getResponseCode() != 200) {
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

  private void applyDownloadPolicy(URI source, java.net.HttpURLConnection connection) throws IOException {
    String policyFile = configuration == null ? null : configuration.getProperty("mpack.download.policy.file");
    if (StringUtils.isBlank(policyFile)) {
      throw new IOException("Network package imports require an administrator-configured artifact source policy");
    }
    Path policyPath = Paths.get(policyFile);
    if (!Files.isRegularFile(policyPath, java.nio.file.LinkOption.NOFOLLOW_LINKS) || Files.size(policyPath) > MAX_METADATA_BYTES) {
      throw new IOException("Invalid artifact source policy file");
    }
    try {
      JsonObject policy = JsonParser.parseString(Files.readString(policyPath)).getAsJsonObject();
      String origin = source.getScheme().toLowerCase(java.util.Locale.ROOT) + "://"
          + source.getHost().toLowerCase(java.util.Locale.ROOT) + ":"
          + (source.getPort() < 0 ? ("https".equalsIgnoreCase(source.getScheme()) ? 443 : 80) : source.getPort());
      JsonObject sources = policy.getAsJsonObject("sources");
      JsonObject allowed = sources == null ? null : sources.getAsJsonObject(origin);
      String prefix = allowed == null ? null : allowed.get("pathPrefix").getAsString();
      if (prefix == null || !prefix.startsWith("/") || !prefix.endsWith("/")
          || !source.normalize().getPath().startsWith(prefix) || source.getRawPath().contains("%")) {
        throw new IOException("Artifact URL is outside the approved origin and path");
      }
      if (allowed.has("credential")) {
        if (!"https".equalsIgnoreCase(source.getScheme())) {
          throw new IOException("Private artifact sources require HTTPS");
        }
        JsonObject reference = allowed.getAsJsonObject("credential");
        org.apache.ambari.server.security.credential.Credential credential = artifactCredentials.getCredential(
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
    } catch (org.apache.ambari.server.AmbariException | RuntimeException invalidPolicy) {
      throw new IOException("Artifact source policy or credential resolution failed");
    }
  }

  private long copyLimited(InputStream input, OutputStream output, long maximumBytes) throws IOException {
    byte[] buffer = new byte[64 * 1024];
    long total = 0;
    int bytesRead;
    while ((bytesRead = input.read(buffer)) != -1) {
      total += bytesRead;
      if (total > maximumBytes) {
        throw new IOException("Content exceeds the allowed size");
      }
      output.write(buffer, 0, bytesRead);
    }
    return total;
  }

  private void verifyCatalogMetadata(MpackEntity entity, Mpack mpack) throws IOException {
    if (mpack.getPublisher() != null && entity.getReleaseMetadata() == null) {
      throw new IOException("Publisher release has no persisted authentication evidence");
    }
    if (entity.getReleaseMetadata() != null
        && !JsonParser.parseString(entity.getReleaseMetadata()).equals(mpack.getAuthoringMetadata())) {
      throw new IOException("Release metadata differs from catalog authority");
    }
  }

  private Mpack readMpackMetadata(Path metadataPath) throws IOException {
    if (!Files.isRegularFile(metadataPath) || Files.size(metadataPath) > MAX_METADATA_BYTES) {
      throw new IOException("Missing or oversized " + MPACK_METADATA + " at " + metadataPath);
    }
    try (Reader reader = Files.newBufferedReader(metadataPath, StandardCharsets.UTF_8)) {
      JsonObject metadata = JsonParser.parseReader(reader).getAsJsonObject();
      Mpack parsed = new Gson().fromJson(metadata, Mpack.class);
      if (parsed == null) {
        throw new IOException("Empty " + MPACK_METADATA + " at " + metadataPath);
      }
      parsed.setAuthoringMetadata(metadata);
      return parsed;
    } catch (JsonParseException | IllegalStateException e) {
      throw new IOException("Invalid " + MPACK_METADATA + " metadata");
    }
  }

  /** Authenticate generated executable definitions before unpacking or publishing. */
  protected void verifyAuthoringArchive(Mpack mpack, Path archive) throws IOException {
    if ("Ed25519".equals(mpack.getSignatureAlgorithm())) {
      MpackTrust.verify(mpack, archive, configuration);
      return;
    }
    if (mpack.getPublisher() != null || mpack.getName().startsWith("publisher-")) {
      throw new IOException("Publisher packages require asymmetric authentication");
    }
    if (mpack.getAuthoringFormat() == null) {
      if (configuration != null && "false".equalsIgnoreCase(configuration.getProperty("mpack.legacy.allow"))) {
        throw new IOException("Legacy executable packages are disabled by administrator policy");
      }
      return;
    }
    if (!"mpack.ambari.apache.org/host-service/v1".equals(mpack.getAuthoringFormat())
        || !"HMAC-SHA256".equals(mpack.getSignatureAlgorithm())
        || mpack.getPackageDigest() == null || !mpack.getPackageDigest().matches("[a-f0-9]{64}")
        || mpack.getManifestDigest() == null || !mpack.getManifestDigest().matches("[a-f0-9]{64}")
        || mpack.getDefinitionSha256() == null || !mpack.getDefinitionSha256().matches("[a-f0-9]{64}")
        || mpack.getSignature() == null || !mpack.getSignature().matches("[a-f0-9]{64}")) {
      throw new IOException("Unsupported or unsigned authoring package");
    }
    String keyFile = configuration == null ? null : configuration.getProperty("mpack.signing.key.file");
    if (StringUtils.isBlank(keyFile)) {
      throw new IOException("Host-service import requires mpack.signing.key.file");
    }
    Path keyPath = Paths.get(keyFile);
    if (!Files.isRegularFile(keyPath, java.nio.file.LinkOption.NOFOLLOW_LINKS)
        || Files.size(keyPath) == 0 || Files.size(keyPath) > 4096) {
      throw new IOException("Invalid mpack signing key file");
    }
    byte[] key = Files.readAllBytes(keyPath);
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      try (InputStream stream = Files.newInputStream(archive)) {
        byte[] buffer = new byte[64 * 1024];
        int count;
        while ((count = stream.read(buffer)) != -1) {
          digest.update(buffer, 0, count);
        }
      }
      if (!MessageDigest.isEqual(digest.digest(), HexFormat.of().parseHex(mpack.getDefinitionSha256()))) {
        throw new IOException("Authoring definition digest mismatch");
      }
      String envelope = "mpack-legacy/v1\n" + mpack.getName() + "\n" + mpack.getVersion() + "\n"
          + mpack.getDefinitionSha256() + "\n" + mpack.getManifestDigest() + "\n"
          + mpack.getPackageDigest() + "\n";
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      if (!MessageDigest.isEqual(mac.doFinal(envelope.getBytes(StandardCharsets.UTF_8)),
          HexFormat.of().parseHex(mpack.getSignature()))) {
        throw new IOException("Authoring package authentication failed");
      }
    } catch (GeneralSecurityException error) {
      throw new IOException("Unable to authenticate authoring package", error);
    } finally {
      java.util.Arrays.fill(key, (byte) 0);
    }
  }

  private void validateMpackMetadata(Mpack mpack) {
    validateIdentifier(mpack.getMpackId(), "mpack id");
    validateIdentifier(mpack.getName(), "mpack name");
    validateIdentifier(mpack.getVersion(), "mpack version");
    validateRelativeArchivePath(mpack.getDefinition(), "mpack definition");
    List<Module> modules = mpack.getModules();
    if (modules == null) {
      throw new IllegalArgumentException("Mpack modules must not be null");
    }

    Set<String> moduleNames = new HashSet<>();
    for (Module module : modules) {
      if (module == null) {
        throw new IllegalArgumentException("Mpack module must not be null");
      }
      validateIdentifier(module.getId(), "module id");
      validateIdentifier(module.getName(), "module name");
      if (module.getCategory() == null || StringUtils.isBlank(module.getVersion())) {
        throw new IllegalArgumentException("Mpack module " + module.getName()
            + " must declare category and version");
      }
      validateRelativeArchivePath(module.getDefinition(), "module definition");
      if (!moduleNames.add(module.getName())) {
        throw new IllegalArgumentException("Duplicate mpack module name: " + module.getName());
      }
      if (module.getComponents() != null) {
        Set<String> componentNames = new HashSet<>();
        for (ModuleComponent component : module.getComponents()) {
          if (component == null) {
            throw new IllegalArgumentException("Mpack module component must not be null");
          }
          validateIdentifier(component.getId(), "module component id");
          validateIdentifier(component.getName(), "module component name");
          if (StringUtils.isBlank(component.getCategory())
              || StringUtils.isBlank(component.getVersion())) {
            throw new IllegalArgumentException("Mpack module component " + component.getName()
                + " must declare category and version");
          }
          if (!componentNames.add(component.getName())) {
            throw new IllegalArgumentException("Duplicate module component name: " + component.getName());
          }
        }
      }
      if (module.getDependencies() != null) {
        Set<String> dependencyIds = new HashSet<>();
        for (ModuleDependency dependency : module.getDependencies()) {
          if (dependency == null) {
            throw new IllegalArgumentException("Mpack module dependency must not be null");
          }
          validateIdentifier(dependency.getId(), "module dependency id");
          validateIdentifier(dependency.getName(), "module dependency name");
          if (dependency.getDependencyType() == null) {
            throw new IllegalArgumentException("Mpack module dependency " + dependency.getName()
                + " must declare type");
          }
          if (!dependencyIds.add(dependency.getId())) {
            throw new IllegalArgumentException("Duplicate module dependency id: "
                + dependency.getId());
          }
        }
      }
    }
    validateOsSpecifics(mpack.getOsSpecifics());
    mpack.populateModuleMap();
  }

  private void validateOsSpecifics(List<MpackOsSpecific> osSpecifics) {
    if (osSpecifics == null) {
      return;
    }
    Set<String> families = new HashSet<>();
    for (MpackOsSpecific osSpecific : osSpecifics) {
      if (osSpecific == null || StringUtils.isBlank(osSpecific.getOsFamily())) {
        throw new IllegalArgumentException("Mpack OS family must not be empty");
      }
      if (!families.add(osSpecific.getOsFamily())) {
        throw new IllegalArgumentException("Duplicate mpack OS family: " + osSpecific.getOsFamily());
      }
      Set<String> packages = new HashSet<>();
      for (String packageName : osSpecific.getPackages()) {
        if (StringUtils.isBlank(packageName)) {
          throw new IllegalArgumentException(
              "Mpack package name must not be empty for OS family " + osSpecific.getOsFamily());
        }
        if (!packages.add(packageName)) {
          throw new IllegalArgumentException("Duplicate mpack package " + packageName
              + " for OS family " + osSpecific.getOsFamily());
        }
      }
    }
  }

  private void validateIdentifier(String value, String field) {
    if (value == null || !IDENTIFIER_PATTERN.matcher(value).matches()) {
      throw new IllegalArgumentException("Invalid " + field + ": " + value);
    }
  }

  private Path validateRelativeArchivePath(String value, String field) {
    if (StringUtils.isBlank(value) || value.indexOf('\\') >= 0) {
      throw new IllegalArgumentException("Invalid " + field + ": " + value);
    }
    try {
      URI reference = new URI(value);
      if (reference.isAbsolute() || reference.getAuthority() != null
          || reference.getQuery() != null || reference.getFragment() != null) {
        throw new IllegalArgumentException("Invalid " + field + ": " + value);
      }
      Path path = Paths.get(reference.getPath()).normalize();
      if (path.isAbsolute() || path.startsWith("..") || path.toString().isEmpty()) {
        throw new IllegalArgumentException("Invalid " + field + ": " + value);
      }
      return path;
    } catch (URISyntaxException e) {
      throw new IllegalArgumentException("Invalid " + field + ": " + value, e);
    }
  }

  private Path finalMpackDirectory(Mpack mpack) {
    return mpackStaging.toPath().toAbsolutePath().normalize()
        .resolve(mpack.getName()).resolve(mpack.getVersion());
  }

  private Path prepareMpack(Path requestDirectory, Path archivePath, Path metadataPath, Mpack mpack)
      throws IOException {
    Path extractionDirectory = requestDirectory.resolve("definition");
    ExpansionBudget budget = new ExpansionBudget();
    extractTar(archivePath, extractionDirectory, budget);
    Path packageRoot = locateArchiveRoot(extractionDirectory, mpack.getDefinition());
    Files.copy(metadataPath, packageRoot.resolve(MPACK_METADATA), StandardCopyOption.REPLACE_EXISTING);
    loadRepositoryMetadata(mpack, packageRoot);
    createServicesDirectory(requestDirectory, packageRoot, mpack, budget);
    Path metainfo = packageRoot.resolve("metainfo.xml");
    if (!Files.exists(metainfo, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      generateMetainfo(metainfo.toFile(), mpack);
    } else if (!Files.isRegularFile(metainfo, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("Mpack metainfo.xml must be a regular file");
    }
    return packageRoot;
  }

  private void loadRepositoryMetadata(Mpack mpack, Path packageRoot) throws IOException {
    RepositoryXml repositoryXml = RepoUtil.getRepositoryXml(packageRoot.toFile());
    if (repositoryXml == null) {
      return;
    }
    if (!repositoryXml.isValid()) {
      throw new IOException("Invalid " + RepoUtil.REPOSITORY_FILE_NAME + " in " + packageRoot
          + ": " + repositoryXml.getErrors());
    }

    Set<String> osFamilies = new HashSet<>();
    Set<String> repositoryKeys = new HashSet<>();
    for (RepositoryXml.Os os : repositoryXml.getOses()) {
      if (os == null || StringUtils.isBlank(os.getFamily())) {
        throw new IOException("Repository OS family must not be empty in " + packageRoot);
      }
      if (!osFamilies.add(os.getFamily())) {
        throw new IOException("Duplicate repository OS family " + os.getFamily() + " in " + packageRoot);
      }
      if (os.getRepos() == null || os.getRepos().isEmpty()) {
        throw new IOException("Repository OS family " + os.getFamily() + " has no repositories");
      }
    }
    for (RepositoryInfo repository : repositoryXml.getRepositories()) {
      if (StringUtils.isBlank(repository.getRepoId()) || StringUtils.isBlank(repository.getBaseUrl())) {
        throw new IOException("Repository id and base URL must not be empty in " + packageRoot);
      }
      String key = repository.getOsType() + '\u0000' + repository.getRepoId();
      if (!repositoryKeys.add(key)) {
        throw new IOException("Duplicate repository " + repository.getRepoId()
            + " for OS " + repository.getOsType());
      }
    }
    mpack.setRepositoryXml(repositoryXml);
  }

  /**
   * Extracts a gzip-compressed tar archive while rejecting links, special
   * entries, traversal and excessive expansion.
   */
  private static final class ExpansionBudget {
    private long bytes;
    private int entries;
  }

  protected void extractTar(Path tarPath, Path destination) throws IOException {
    extractTar(tarPath, destination, new ExpansionBudget());
  }

  private void extractTar(Path tarPath, Path destination, ExpansionBudget budget) throws IOException {
    Path normalizedDestination = destination.toAbsolutePath().normalize();
    Files.createDirectories(normalizedDestination);

    try (InputStream fileInput = new BufferedInputStream(new FileInputStream(tarPath.toFile()));
        GzipCompressorInputStream gzipInput = new GzipCompressorInputStream(fileInput);
        TarArchiveInputStream tarInput = new TarArchiveInputStream(gzipInput)) {
      TarArchiveEntry entry;
      while ((entry = tarInput.getNextTarEntry()) != null) {
        if (++budget.entries > MAX_ARCHIVE_ENTRIES) {
          throw new IOException("Archive contains too many entries");
        }
        if (entry.isSymbolicLink() || entry.isLink() || (!entry.isDirectory() && !entry.isFile())) {
          throw new IOException("Archive contains an unsupported entry: " + entry.getName());
        }

        Path relativePath;
        try {
          relativePath = Paths.get(entry.getName()).normalize();
        } catch (RuntimeException e) {
          throw new IOException("Archive contains an invalid path: " + entry.getName(), e);
        }
        if (relativePath.isAbsolute() || relativePath.startsWith("..")) {
          throw new IOException("Archive entry escapes the destination: " + entry.getName());
        }
        Path outputPath = normalizedDestination.resolve(relativePath).normalize();
        if (!outputPath.startsWith(normalizedDestination)) {
          throw new IOException("Archive entry escapes the destination: " + entry.getName());
        }

        if (entry.isDirectory()) {
          Files.createDirectories(outputPath);
        } else {
          Files.createDirectories(outputPath.getParent());
          try (OutputStream output = new BufferedOutputStream(Files.newOutputStream(outputPath,
              StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
            budget.bytes += copyLimited(tarInput, output, MAX_EXPANDED_BYTES - budget.bytes);
          }
        }
      }
    }
  }

  private Path locateArchiveRoot(Path extractionDirectory, String definition) throws IOException {
    String fileName = Paths.get(definition).getFileName().toString();
    Path expectedRoot = extractionDirectory.resolve(stripArchiveExtension(fileName));
    if (Files.isDirectory(expectedRoot)) {
      return expectedRoot;
    }
    List<Path> children;
    try (java.util.stream.Stream<Path> stream = Files.list(extractionDirectory)) {
      children = stream.collect(Collectors.toList());
    }
    if (children.size() == 1 && Files.isDirectory(children.get(0))) {
      return children.get(0);
    }
    return extractionDirectory;
  }

  private String stripArchiveExtension(String fileName) {
    if (fileName.endsWith(".tar.gz")) {
      return fileName.substring(0, fileName.length() - ".tar.gz".length());
    }
    if (fileName.endsWith(".tgz")) {
      return fileName.substring(0, fileName.length() - ".tgz".length());
    }
    throw new IllegalArgumentException("Mpack definitions must be .tar.gz or .tgz archives: " + fileName);
  }

  private void createServicesDirectory(Path requestDirectory, Path packageRoot, Mpack mpack,
      ExpansionBudget budget) throws IOException {
    Path servicesDirectory = packageRoot.resolve(MODULES_DIRECTORY);
    Files.createDirectories(servicesDirectory);
    int moduleIndex = 0;
    for (Module module : mpack.getModules()) {
      Path relativeDefinition = validateRelativeArchivePath(module.getDefinition(), "module definition");
      Path modulesRoot = packageRoot.resolve(MODULE_ARCHIVES_DIRECTORY).normalize();
      Path moduleArchive = modulesRoot.resolve(relativeDefinition).normalize();
      if (!moduleArchive.startsWith(modulesRoot) || !Files.isRegularFile(moduleArchive)) {
        throw new IOException("Missing module archive " + module.getDefinition());
      }

      Path moduleExtraction = requestDirectory.resolve("module-" + moduleIndex++);
      extractTar(moduleArchive, moduleExtraction, budget);
      Path extractedModuleRoot = locateArchiveRoot(moduleExtraction, module.getDefinition());
      if (Files.exists(extractedModuleRoot.resolve("package/manifest-service.json"))
          && mpack.getAuthoringFormat() == null) {
        throw new IOException("Declarative host definitions require authenticated authoring metadata");
      }
      moveDirectory(extractedModuleRoot, servicesDirectory.resolve(module.getName()));
    }
  }

  private void generateMetainfo(File metainfoFile, Mpack mpack) throws IOException {
    StackMetainfoXml generatedMetainfo = new StackMetainfoXml();
    StackMetainfoXml.Version version = new StackMetainfoXml.Version();
    version.setActive(true);
    generatedMetainfo.setVersion(version);
    Map<String, String> prerequisites = mpack.getPrerequisites();
    generatedMetainfo.setMinJdk(prerequisites == null
        ? DEFAULT_JDK_VALUE : prerequisites.getOrDefault(MIN_JDK_PROPERTY, DEFAULT_JDK_VALUE));
    generatedMetainfo.setMaxJdk(prerequisites == null
        ? DEFAULT_JDK_VALUE : prerequisites.getOrDefault(MAX_JDK_PROPERTY, DEFAULT_JDK_VALUE));

    try {
      JAXBContext context = JAXBContext.newInstance(StackMetainfoXml.class);
      Marshaller marshaller = context.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
      try (FileOutputStream output = new FileOutputStream(metainfoFile)) {
        marshaller.marshal(generatedMetainfo, output);
      }
    } catch (JAXBException e) {
      throw new IOException("Unable to generate " + metainfoFile, e);
    }
  }

  private void moveDirectory(Path source, Path target) throws IOException {
    try {
      Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
    } catch (java.nio.file.AtomicMoveNotSupportedException e) {
      Files.move(source, target);
    }
  }

  private Path createStackProjection(Mpack mpack, Path mpackDirectory) throws IOException {
    Path stackNameDirectory = stackRoot.toPath().toAbsolutePath().normalize().resolve(mpack.getStackName());
    Files.createDirectories(stackNameDirectory);
    Path stackPath = stackNameDirectory.resolve(mpack.getVersion());
    if (Files.exists(stackPath, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      throw new FileAlreadyExistsException(stackPath.toString());
    }

    Path temporaryLink = stackNameDirectory.resolve("." + mpack.getVersion() + ".mpack-" + UUID.randomUUID());
    try {
      Files.createSymbolicLink(temporaryLink, mpackDirectory.toAbsolutePath().normalize());
      try {
        Files.move(temporaryLink, stackPath, StandardCopyOption.ATOMIC_MOVE);
      } catch (java.nio.file.AtomicMoveNotSupportedException e) {
        Files.move(temporaryLink, stackPath);
      }
      return stackPath;
    } finally {
      Files.deleteIfExists(temporaryLink);
    }
  }

  private void rollbackRegistration(Long mpackId, boolean stackPersisted, Path stackLink, Path mpackDirectory) {
    if (mpackId != null) {
      if (stackPersisted) {
        try {
          stackDAO.removeByMpack(mpackId);
        } catch (RuntimeException e) {
          LOG.error("Unable to roll back stack metadata for mpack {}; retaining files for recovery", mpackId, e);
          return;
        }
      }
      try {
        mpackDAO.removeById(mpackId);
      } catch (RuntimeException e) {
        LOG.error("Unable to roll back mpack metadata for mpack {}; retaining files for recovery", mpackId, e);
        return;
      }
      mpackMap.remove(mpackId);
    }
    if (stackLink != null) {
      try {
        Files.deleteIfExists(stackLink);
        deleteDirectoryIfEmpty(stackLink.getParent());
      } catch (IOException e) {
        LOG.error("Unable to roll back mpack stack projection {}", stackLink, e);
      }
    }
    if (mpackDirectory != null) {
      try {
        FileUtils.deleteDirectory(mpackDirectory.toFile());
        deleteDirectoryIfEmpty(mpackDirectory.getParent());
      } catch (IOException e) {
        LOG.error("Unable to roll back mpack directory {}", mpackDirectory, e);
      }
    }
  }

  private void deleteDirectoryIfEmpty(Path directory) throws IOException {
    if (directory == null) {
      return;
    }
    try {
      Files.delete(directory);
    } catch (DirectoryNotEmptyException | java.nio.file.NoSuchFileException ignored) {
      // The parent belongs to another version or has already been removed.
    }
  }

  /**
   * Downloads a definition archive to a request-unique staging directory.
   * The caller owns cleanup of the returned parent directory.
   */
  public Path downloadMpack(String mpackURI, String mpackDefinitionLocation) throws IOException {
    URI metadataUri = parseMpackUri(mpackURI);
    URI archiveUri = resolveDefinitionUri(metadataUri, mpackDefinitionLocation);
    Path stagingDirectory = mpackStaging.toPath().toAbsolutePath().normalize().resolve(MPACK_TAR_LOCATION);
    Files.createDirectories(stagingDirectory);
    Path requestDirectory = Files.createTempDirectory(stagingDirectory, "download-");
    Path target = requestDirectory.resolve("mpack-definition.tar.gz");
    try {
      download(archiveUri, target, MAX_ARCHIVE_BYTES);
      return target;
    } catch (IOException | RuntimeException e) {
      FileUtils.deleteQuietly(requestDirectory.toFile());
      throw e;
    }
  }

  protected boolean validateMpackInfo(String expectedMpackName, String expectedMpackVersion,
      String actualMpackName, String actualMpackVersion) {
    return StringUtils.equalsIgnoreCase(expectedMpackName, actualMpackName)
        && StringUtils.equalsIgnoreCase(expectedMpackVersion, actualMpackVersion);
  }

  protected Long populateDB(Mpack mpack) throws IOException {
    if (!mpackDAO.findByNameVersion(mpack.getName(), mpack.getVersion()).isEmpty()
        || stackDAO.find(mpack.getStackName(), mpack.getVersion()) != null) {
      return null;
    }
    MpackEntity entity = new MpackEntity();
    entity.setMpackName(mpack.getName());
    entity.setMpackVersion(mpack.getVersion());
    entity.setMpackUri(mpack.getMpackUri());
    entity.setRegistryId(mpack.getRegistryId());
    entity.setContentDigest(mpack.getPackageDigest());
    if (mpack.getAuthoringMetadata() != null) {
      entity.setReleaseMetadata(mpack.getAuthoringMetadata().toString());
    }
    return mpackDAO.create(entity);
  }

  protected void populateStackDB(Mpack mpack) throws IOException, ResourceAlreadyExistsException {
    if (stackDAO.find(mpack.getStackName(), mpack.getVersion()) != null) {
      throw new ResourceAlreadyExistsException(
          "Stack " + mpack.getName() + "-" + mpack.getVersion() + " already exists");
    }
    StackEntity stackEntity = new StackEntity();
    stackEntity.setStackName(mpack.getStackName());
    stackEntity.setStackVersion(mpack.getVersion());
    stackEntity.setMpackId(mpack.getResourceId());
    stackDAO.create(stackEntity);
  }

  public List<Module> getModules(Long mpackId) {
    Mpack mpack = mpackMap.get(mpackId);
    return mpack == null ? Collections.emptyList() : mpack.getModules();
  }

  /**
   * Commit deletion under existing DB foreign keys before changing projections.
   * A local intent marker allows restart reconciliation after a lost response;
   * quarantined definitions are retained and are never treated as runtime data.
   */
  public boolean removeMpack(MpackEntity entity, StackEntity stack) throws IOException {
    if (entity == null) {
      return false;
    }
    synchronized (registrationLock) {
      validateIdentifier(entity.getMpackName(), "mpack name");
      validateIdentifier(entity.getMpackVersion(), "mpack version");
      Path directory = mpackStaging.toPath().toAbsolutePath().normalize()
          .resolve(entity.getMpackName()).resolve(entity.getMpackVersion());
      if (Files.isDirectory(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
        try (FileOutputStream marker = new FileOutputStream(directory.resolve(DELETION_PENDING).toFile())) {
          marker.write("deletion/v1\n".getBytes(StandardCharsets.UTF_8));
          marker.getFD().sync();
        }
      }
      try {
        mpackDAO.removeCatalog(entity.getId());
      } catch (RuntimeException error) {
        throw new IOException("Mpack catalog deletion failed; definitions are retained", error);
      }
      mpackMap.remove(entity.getId());
      try {
        if (Files.isDirectory(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
          quarantineIncompleteRegistration(directory);
        }
      } catch (IOException error) {
        LOG.warn("Catalog deletion committed; filesystem cleanup will resume on restart", error);
      }
      return stack != null;
    }
  }

  private void removeLegacyProjection(Mpack mpack, Path directory) throws IOException {
    if (mpack.getName().equals(mpack.getStackName())) {
      return;
    }
    Path old = stackRoot.toPath().toAbsolutePath().normalize().resolve(mpack.getName()).resolve(mpack.getVersion());
    if (Files.isSymbolicLink(old)
        && old.getParent().resolve(Files.readSymbolicLink(old)).normalize().equals(directory.toAbsolutePath().normalize())) {
      Files.delete(old);
      deleteDirectoryIfEmpty(old.getParent());
    }
  }

  private void ensureStackProjection(Mpack mpack, Path directory) throws IOException {
    Path link = stackRoot.toPath().toAbsolutePath().normalize()
        .resolve(mpack.getStackName()).resolve(mpack.getVersion());
    if (!Files.exists(link, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      createStackProjection(mpack, directory);
    } else if (!Files.isSymbolicLink(link)
        || !link.getParent().resolve(Files.readSymbolicLink(link)).normalize().equals(directory.toAbsolutePath().normalize())) {
      throw new IOException("Stack projection is owned by another package");
    }
    removeLegacyProjection(mpack, directory);
  }

  private void quarantineIncompleteRegistration(Path directory) throws IOException {
    if (!Files.isRegularFile(directory.resolve(REGISTRATION_PENDING), java.nio.file.LinkOption.NOFOLLOW_LINKS)
        && !Files.isRegularFile(directory.resolve(DELETION_PENDING), java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      LOG.warn("Unregistered mpack directory retained for operator review: {}", directory);
      return;
    }
    Mpack removed = readMpackMetadata(directory.resolve(MPACK_METADATA));
    Path link = stackRoot.toPath().toAbsolutePath().normalize()
        .resolve(removed.getStackName()).resolve(directory.getFileName());
    if (Files.isSymbolicLink(link)
        && link.getParent().resolve(Files.readSymbolicLink(link)).normalize().equals(directory.toAbsolutePath().normalize())) {
      Files.delete(link);
    } else if (Files.exists(link, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("Cannot recover registration with a conflicting stack projection");
    }
    Path quarantine = mpackStaging.toPath().resolve(MPACK_TAR_LOCATION).resolve("quarantine");
    Files.createDirectories(quarantine);
    moveDirectory(directory, quarantine.resolve(UUID.randomUUID().toString()));
    LOG.warn("Incomplete registration retained in quarantine; original name can be registered again");
  }
}
