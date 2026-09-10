/**
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
package org.apache.ambari.server.state;


import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.ambari.server.state.stack.RepositoryXml;
import org.apache.commons.lang3.builder.EqualsBuilder;

import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * Represents the state of an mpack.
 */
public class Mpack {

  /**
   * Mpack DB Id
   */
  private Long resourceId;

  private Long registryId;

  /**
   * Mpack id as defined in mpack.json
   */
  @SerializedName("id")
  private String mpackId;

  @SerializedName("name")
  private String name;

  @SerializedName("version")
  private String version;


  @SerializedName("prerequisites")
  private HashMap<String, String> prerequisites;

  @SerializedName("modules")
  private List<Module> modules;

  @SerializedName("osSpecifics")
  private List<MpackOsSpecific> osSpecifics;

  @SerializedName("definition")
  private String definition;

  @SerializedName("description")
  private String description;

  @SerializedName("displayName")
  private String displayName;

  private String authoringFormat;
  private String manifestDigest;
  private String packageDigest;
  private String definitionSha256;
  private String signatureAlgorithm;
  private String signature;
  private String publisher;
  private String packageName;
  private String signatureKeyId;
  private String signatureFormat;
  private Map<String, String> compatibility;
  private Map<String, String> softwareVersions;
  private transient JsonObject authoringMetadata;
  private transient Long repositoryVersionId;

  public Long getRepositoryVersionId() { return repositoryVersionId; }
  public void setRepositoryVersionId(Long value) { repositoryVersionId = value; }

  public String getPublisher() { return publisher; }
  public String getPackageName() { return packageName; }
  public String getSignatureKeyId() { return signatureKeyId; }
  public String getSignatureFormat() { return signatureFormat; }
  public Map<String, String> getCompatibility() { return compatibility; }
  public Map<String, String> getSoftwareVersions() { return softwareVersions; }
  public JsonObject getAuthoringMetadata() { return authoringMetadata; }
  public void setAuthoringMetadata(JsonObject value) { authoringMetadata = value; }

  public String getAuthoringFormat() { return authoringFormat; }
  public String getManifestDigest() { return manifestDigest; }
  public String getPackageDigest() { return packageDigest; }
  public String getDefinitionSha256() { return definitionSha256; }
  public String getSignatureAlgorithm() { return signatureAlgorithm; }
  public String getSignature() { return signature; }

  private String mpackUri;

  private transient RepositoryXml repositoryXml;

  private transient Map<String, Module> moduleMap = new HashMap<>();

  public Long getResourceId() {
    return resourceId;
  }

  public void setResourceId(Long resourceId) {
    this.resourceId = resourceId;
  }

  public Long getRegistryId() {
    return registryId;
  }

  public void setRegistryId(Long registryId) {
    this.registryId = registryId;
  }

  public String getMpackUri() {
    return mpackUri;
  }

  public void setMpackUri(String mpackUri) {
    this.mpackUri = mpackUri;
  }

  public String getMpackId() {
    return mpackId;
  }

  public void setMpackId(String mpackId) {
    this.mpackId = mpackId;
  }

  /** The publisher envelope keeps installation inventory separate from legacy prerequisites. */
  @SuppressWarnings("unchecked")
  public java.util.Map<String, Object> getInstallationPrerequisites() {
    if (authoringMetadata == null || !authoringMetadata.has("installationPrerequisites")) {
      return java.util.Collections.emptyMap();
    }
    return new com.google.gson.Gson().fromJson(authoringMetadata.get("installationPrerequisites"), java.util.Map.class);
  }

  /** Legacy StackId strings reserve the first hyphen for the version separator. */
  public String getStackName() {
    return packageDigest == null ? name : "MPACK_" + org.apache.commons.codec.digest.DigestUtils.sha256Hex(name);
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getVersion() {
    return version;
  }

  public void setVersion(String version) {
    this.version = version;
  }

  public String getDescription() {
    return description;
  }

  public void setDescription(String description) {
    this.description = description;
  }

  public HashMap<String, String> getPrerequisites() {
    return prerequisites;
  }

  public void setPrerequisites(HashMap<String, String> prerequisites) {
    this.prerequisites = prerequisites;
  }

  public List<Module> getModules() {
    return modules;
  }

  public void setModules(List<Module> modules) {
    this.modules = modules;
    populateModuleMap();
  }

  public List<MpackOsSpecific> getOsSpecifics() {
    return osSpecifics;
  }

  public void setOsSpecifics(List<MpackOsSpecific> osSpecifics) {
    this.osSpecifics = osSpecifics;
  }

  public RepositoryXml getRepositoryXml() {
    return repositoryXml;
  }

  public void setRepositoryXml(RepositoryXml repositoryXml) {
    this.repositoryXml = repositoryXml;
  }

  public String getDefinition() {
    return definition;
  }

  public void setDefinition(String definition) {
    this.definition = definition;
  }

  public String getDisplayName() {
    return displayName;
  }

  public void setDisplayName(String displayName) {
    this.displayName = displayName;
  }

  /**
   * Gets the module with the given name. Module names are service names.
   *
   * @param moduleName
   *          the name of the module.
   * @return the module or {@code null}.
   */
  public Module getModule(String moduleName) {
    ensureModuleMap();
    return moduleMap.get(moduleName);
  }

  /**
   * Gets a component from a given module.
   *
   * @param moduleName
   *          the module (service) name.
   * @param moduleComponentName
   *          the name of the component.
   * @return the component or {@code null}.
   */
  public ModuleComponent getModuleComponent(String moduleName, String moduleComponentName) {
    Module module = getModule(moduleName);
    return module == null ? null : module.getModuleComponent(moduleComponentName);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    Mpack that = (Mpack) o;
    EqualsBuilder equalsBuilder = new EqualsBuilder();
    equalsBuilder.append(resourceId, that.resourceId);
    equalsBuilder.append(registryId, that.registryId);
    equalsBuilder.append(mpackId, that.mpackId);
    equalsBuilder.append(name, that.name);
    equalsBuilder.append(version, that.version);
    equalsBuilder.append(prerequisites, that.prerequisites);
    equalsBuilder.append(modules, that.modules);
    equalsBuilder.append(osSpecifics, that.osSpecifics);
    equalsBuilder.append(definition, that.definition);
    equalsBuilder.append(description, that.description);
    equalsBuilder.append(mpackUri, that.mpackUri);
    equalsBuilder.append(displayName, that.displayName);

    return equalsBuilder.isEquals();
  }

  @Override
  public int hashCode() {
    return Objects.hash(resourceId, registryId, mpackId, name, version, prerequisites, modules,
        osSpecifics, definition, description, mpackUri, displayName);
  }

  @Override
  public String toString() {
    return "Mpack{" +
            "id=" + resourceId +
            ", registryId=" + registryId +
            ", mpackId='" + mpackId + '\'' +
            ", name='" + name + '\'' +
            ", version='" + version + '\'' +
            ", prerequisites=" + prerequisites +
            ", modules=" + modules +
            ", osSpecifics=" + osSpecifics +
            ", definition='" + definition + '\'' +
            ", description='" + description + '\'' +
            ", displayName='" + displayName + '\'' +
            '}';
  }

  public void copyFrom(Mpack mpack) {
    if (this.resourceId == null) {
      this.resourceId = mpack.getResourceId();
    }
    if (this.name == null) {
      this.name = mpack.getName();
    }
    if (this.mpackId == null)
      this.mpackId = mpack.getMpackId();
    if (this.version == null)
      this.version = mpack.getVersion();
    if (this.registryId == null) {
      this.registryId = mpack.getRegistryId();
    }
    if (this.description == null)
      this.description = mpack.getDescription();
    if (this.modules == null) {
      setModules(mpack.getModules());
    }
    if (this.prerequisites == null) {
      this.prerequisites = mpack.getPrerequisites();
    }
    if (this.osSpecifics == null) {
      this.osSpecifics = mpack.getOsSpecifics();
    }
    if (this.repositoryXml == null) {
      this.repositoryXml = mpack.getRepositoryXml();
    }
    if (this.definition == null) {
      this.definition = mpack.getDefinition();
    }
    if (displayName == null) {
      displayName = mpack.getDisplayName();
    }
    if (mpackUri == null) {
      mpackUri = mpack.getMpackUri();
    }
  }

  /**
   * Builds deterministic lookup maps after JSON deserialization.
   */
  public void populateModuleMap() {
    moduleMap = new HashMap<>();
    if (modules == null) {
      return;
    }
    for (Module module : modules) {
      if (module != null) {
        module.populateComponentMap();
        moduleMap.put(module.getName(), module);
      }
    }
  }

  private void ensureModuleMap() {
    if (moduleMap == null || (moduleMap.isEmpty() && modules != null && !modules.isEmpty())) {
      populateModuleMap();
    }
  }
}
