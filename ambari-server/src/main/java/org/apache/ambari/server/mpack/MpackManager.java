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
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import jakarta.xml.bind.Marshaller;

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
import com.google.inject.assistedinject.Assisted;
import com.google.inject.assistedinject.AssistedInject;

/**
 * Manages mpack metadata, registration and its compatibility projection into
 * the Stack resource tree.
 */
public class MpackManager {
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
          existingMpack.setResourceId(entity.getId());
          existingMpack.setMpackUri(entity.getMpackUri());
          existingMpack.setRegistryId(entity.getRegistryId());
          mpackMap.put(entity.getId(), existingMpack);
        } catch (IOException | RuntimeException e) {
          LOG.error("Unable to load registered mpack {}-{} from {}", mpackName, mpackVersion,
              versionDirectory, e);
        }
      }
    }
  }

  public Map<Long, Mpack> getMpackMap() {
    return Collections.unmodifiableMap(mpackMap);
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
    synchronized (registrationLock) {
      return registerMpackLocked(request);
    }
  }

  private MpackResponse registerMpackLocked(MpackRequest request)
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
      download(metadataUri, metadataPath, MAX_METADATA_BYTES);
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
      assertMpackAvailable(mpack, finalDirectory);
      URI archiveUri = resolveDefinitionUri(metadataUri, mpack.getDefinition());
      Path archivePath = requestDirectory.resolve("mpack-definition.tar.gz");
      download(archiveUri, archivePath, MAX_ARCHIVE_BYTES);
      Path preparedDirectory = prepareMpack(requestDirectory, archivePath, metadataPath, mpack);

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
      mpackMap.put(mpackResourceId, mpack);
      return new MpackResponse(mpack);
    } catch (IOException | IllegalArgumentException | ResourceAlreadyExistsException e) {
      rollbackRegistration(mpackResourceId, stackPersisted, stackLink, publishedDirectory);
      throw e;
    } catch (RuntimeException e) {
      rollbackRegistration(mpackResourceId, stackPersisted, stackLink, publishedDirectory);
      throw e;
    } finally {
      FileUtils.deleteQuietly(requestDirectory.toFile());
    }
  }

  private void assertMpackAvailable(Mpack mpack, Path finalDirectory)
      throws ResourceAlreadyExistsException {
    if (!mpackDAO.findByNameVersion(mpack.getName(), mpack.getVersion()).isEmpty()
        || stackDAO.find(mpack.getName(), mpack.getVersion()) != null
        || Files.exists(finalDirectory, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
      throw duplicateMpack(mpack);
    }
  }

  private ResourceAlreadyExistsException duplicateMpack(Mpack mpack) {
    return new ResourceAlreadyExistsException(
        "Mpack " + mpack.getName() + " version " + mpack.getVersion() + " already exists in server");
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

  private void download(URI source, Path target, long maximumBytes) throws IOException {
    URLConnection connection = source.toURL().openConnection();
    connection.setUseCaches(false);
    connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
    connection.setReadTimeout(READ_TIMEOUT_MILLIS);
    long declaredLength = connection.getContentLengthLong();
    if (declaredLength > maximumBytes) {
      throw new IOException("Remote content exceeds the allowed size");
    }

    Files.createDirectories(target.getParent());
    try (InputStream input = new BufferedInputStream(connection.getInputStream());
        OutputStream output = new BufferedOutputStream(Files.newOutputStream(target,
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
      copyLimited(input, output, maximumBytes);
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

  private Mpack readMpackMetadata(Path metadataPath) throws IOException {
    if (!Files.isRegularFile(metadataPath) || Files.size(metadataPath) > MAX_METADATA_BYTES) {
      throw new IOException("Missing or oversized " + MPACK_METADATA + " at " + metadataPath);
    }
    try (Reader reader = Files.newBufferedReader(metadataPath, StandardCharsets.UTF_8)) {
      Mpack parsed = new Gson().fromJson(reader, Mpack.class);
      if (parsed == null) {
        throw new IOException("Empty " + MPACK_METADATA + " at " + metadataPath);
      }
      return parsed;
    } catch (JsonParseException e) {
      throw new IOException("Invalid " + MPACK_METADATA + " at " + metadataPath, e);
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
    extractTar(archivePath, extractionDirectory);
    Path packageRoot = locateArchiveRoot(extractionDirectory, mpack.getDefinition());
    Files.copy(metadataPath, packageRoot.resolve(MPACK_METADATA), StandardCopyOption.REPLACE_EXISTING);
    loadRepositoryMetadata(mpack, packageRoot);
    createServicesDirectory(requestDirectory, packageRoot, mpack);
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
  protected void extractTar(Path tarPath, Path destination) throws IOException {
    Path normalizedDestination = destination.toAbsolutePath().normalize();
    Files.createDirectories(normalizedDestination);
    long expandedBytes = 0;
    int entries = 0;

    try (InputStream fileInput = new BufferedInputStream(new FileInputStream(tarPath.toFile()));
        GzipCompressorInputStream gzipInput = new GzipCompressorInputStream(fileInput);
        TarArchiveInputStream tarInput = new TarArchiveInputStream(gzipInput)) {
      TarArchiveEntry entry;
      while ((entry = tarInput.getNextTarEntry()) != null) {
        if (++entries > MAX_ARCHIVE_ENTRIES) {
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
            expandedBytes += copyLimited(tarInput, output, MAX_EXPANDED_BYTES - expandedBytes);
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

  private void createServicesDirectory(Path requestDirectory, Path packageRoot, Mpack mpack) throws IOException {
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
      extractTar(moduleArchive, moduleExtraction);
      Path extractedModuleRoot = locateArchiveRoot(moduleExtraction, module.getDefinition());
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
    Path stackNameDirectory = stackRoot.toPath().toAbsolutePath().normalize().resolve(mpack.getName());
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
          LOG.error("Unable to roll back stack metadata for mpack {}", mpackId, e);
        }
      }
      try {
        mpackDAO.removeById(mpackId);
      } catch (RuntimeException e) {
        LOG.error("Unable to roll back mpack metadata for mpack {}", mpackId, e);
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
        || stackDAO.find(mpack.getName(), mpack.getVersion()) != null) {
      return null;
    }
    MpackEntity entity = new MpackEntity();
    entity.setMpackName(mpack.getName());
    entity.setMpackVersion(mpack.getVersion());
    entity.setMpackUri(mpack.getMpackUri());
    entity.setRegistryId(mpack.getRegistryId());
    return mpackDAO.create(entity);
  }

  protected void populateStackDB(Mpack mpack) throws IOException, ResourceAlreadyExistsException {
    if (stackDAO.find(mpack.getName(), mpack.getVersion()) != null) {
      throw new ResourceAlreadyExistsException(
          "Stack " + mpack.getName() + "-" + mpack.getVersion() + " already exists");
    }
    StackEntity stackEntity = new StackEntity();
    stackEntity.setStackName(mpack.getName());
    stackEntity.setStackVersion(mpack.getVersion());
    stackEntity.setMpackId(mpack.getResourceId());
    stackDAO.create(stackEntity);
  }

  public List<Module> getModules(Long mpackId) {
    Mpack mpack = mpackMap.get(mpackId);
    return mpack == null ? Collections.emptyList() : mpack.getModules();
  }

  /**
   * Removes the filesystem projection for an mpack. Persistence is removed by
   * the authorized resource-provider transaction after this method succeeds.
   */
  public boolean removeMpack(MpackEntity mpackEntity, StackEntity stackEntity) throws IOException {
    if (mpackEntity == null) {
      return false;
    }
    validateIdentifier(mpackEntity.getMpackName(), "mpack name");
    validateIdentifier(mpackEntity.getMpackVersion(), "mpack version");
    Path mpackDirectory = mpackStaging.toPath().toAbsolutePath().normalize()
        .resolve(mpackEntity.getMpackName()).resolve(mpackEntity.getMpackVersion());

    boolean stackDelete = false;
    if (stackEntity != null) {
      validateIdentifier(stackEntity.getStackName(), "stack name");
      validateIdentifier(stackEntity.getStackVersion(), "stack version");
      Path stackPath = stackRoot.toPath().toAbsolutePath().normalize()
          .resolve(stackEntity.getStackName()).resolve(stackEntity.getStackVersion());
      if (Files.exists(stackPath, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
        if (!Files.isSymbolicLink(stackPath)) {
          throw new IOException("Refusing to remove non-symlink stack projection " + stackPath);
        }
        Path linkTarget = Files.readSymbolicLink(stackPath);
        Path resolvedTarget = stackPath.getParent().resolve(linkTarget).toAbsolutePath().normalize();
        if (!resolvedTarget.equals(mpackDirectory)) {
          throw new IOException("Refusing to remove stack projection owned by another mpack " + stackPath);
        }
        Files.delete(stackPath);
      }
      deleteDirectoryIfEmpty(stackPath.getParent());
      stackDelete = true;
    }

    FileUtils.deleteDirectory(mpackDirectory.toFile());
    deleteDirectoryIfEmpty(mpackDirectory.getParent());

    String legacyArchiveName = mpackEntity.getMpackName() + "-" + mpackEntity.getMpackVersion() + ".tar.gz";
    Path legacyArchive = mpackStaging.toPath().toAbsolutePath().normalize()
        .resolve(MPACK_TAR_LOCATION).resolve(legacyArchiveName);
    Files.deleteIfExists(legacyArchive);
    mpackMap.remove(mpackEntity.getId());
    return stackDelete;
  }
}
