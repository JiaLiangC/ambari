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
package org.apache.ambari.server.registry;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.ambari.server.AmbariException;
import org.apache.ambari.server.controller.AmbariManagementController;
import org.apache.ambari.server.registry.RegistryRecommendationResponse.RegistryRecommendationResponseBuilder;
import org.apache.ambari.server.registry.RegistryRecommendationResponse.RegistryRecommendations;
import org.apache.ambari.server.registry.RegistryValidationResponse.RegistryValidationResponseBuilder;
import org.apache.ambari.server.registry.RegistryValidationResponse.RegistryValidationResult;
import org.apache.ambari.server.utils.MpackVersion;
import org.apache.commons.lang3.StringUtils;

import com.google.inject.Inject;
import com.google.inject.Singleton;

/**
 * Produces bounded, registry-driven mpack recommendations and validations.
 */
@Singleton
public class RegistryAdvisor {
  private static final int MAX_BUNDLES = 10000;
  private static final int MAX_MPACKS_PER_BUNDLE = 64;
  private static final int MAX_SEARCH_STATES = 100000;

  private static final String FATAL = "FATAL";
  private static final String SCENARIO_VALIDATION = "ScenarioMpackValidation";
  private static final String UNKNOWN_VALIDATION = "UnknownMpackValidation";
  private static final String COMPATIBILITY_VALIDATION = "CompatibleMpackValidation";
  private static final String UPGRADE_VALIDATION = "UpgradeMpackValidation";

  private final AmbariManagementController managementController;
  private final AtomicLong requestId = new AtomicLong();

  @Inject
  public RegistryAdvisor(AmbariManagementController managementController) {
    this.managementController = managementController;
  }

  /**
   * Returns registry recommendations for a scenario or an mpack upgrade.
   */
  public RegistryRecommendationResponse recommend(RegistryAdvisorRequest request) throws AmbariException {
    validateRequest(request);
    switch (request.getRequestType()) {
      case SCENARIO_MPACKS:
        return recommendScenarioMpacks(request);
      case UPGRADE_MPACKS:
        return recommendUpgradeMpacks(request);
      default:
        throw new AmbariException("Unknown registry advisor request type: " + request.getRequestType());
    }
  }

  /**
   * Validates a selected scenario bundle or proposed upgrade bundle.
   */
  public RegistryValidationResponse validate(RegistryAdvisorRequest request) throws AmbariException {
    validateRequest(request);
    switch (request.getRequestType()) {
      case SCENARIO_MPACKS:
        return validateScenarioMpacks(request);
      case UPGRADE_MPACKS:
        return validateUpgradeMpacks(request);
      default:
        throw new AmbariException("Unknown registry advisor request type: " + request.getRequestType());
    }
  }

  private RegistryRecommendationResponse recommendScenarioMpacks(RegistryAdvisorRequest request)
      throws AmbariException {
    Registry registry = managementController.getRegistry(request.getRegistryId());
    Set<String> roots = getScenarioMpacks(registry, request.getSelectedScenarios());
    List<List<MpackEntry>> bundles = resolveBundles(registry, roots, Collections.emptyMap());
    return recommendationResponse(request, bundles);
  }

  private RegistryRecommendationResponse recommendUpgradeMpacks(RegistryAdvisorRequest request)
      throws AmbariException {
    List<MpackEntry> selected = requireSelectedMpacks(request, "upgrade recommendations");
    if (selected.size() != 1) {
      throw new AmbariException("Exactly one current mpack must be selected for upgrade recommendations");
    }

    Registry registry = managementController.getRegistry(request.getRegistryId());
    MpackEntry current = selected.get(0);
    RegistryMpack registryMpack = registry.getRegistryMpack(requireName(current));
    MpackVersion currentVersion = parseVersion(current.getMpackVersion(), current.getMpackName());
    List<RegistryMpackVersion> targets = sortedVersions(registryMpack);
    List<List<MpackEntry>> bundles = new ArrayList<>();

    for (RegistryMpackVersion target : targets) {
      if (compareVersions(target.getMpackVersion(), currentVersion, current.getMpackName()) <= 0) {
        continue;
      }
      MpackEntry fixedTarget = createEntry(registryMpack.getMpackName(), target);
      Map<String, MpackEntry> fixed = Collections.singletonMap(fixedTarget.getMpackName(), fixedTarget);
      List<List<MpackEntry>> targetBundles = resolveBundles(
          registry, Collections.singleton(fixedTarget.getMpackName()), fixed);
      for (List<MpackEntry> bundle : targetBundles) {
        if (bundles.size() == MAX_BUNDLES) {
          return recommendationResponse(request, bundles);
        }
        bundles.add(bundle);
      }
    }
    return recommendationResponse(request, bundles);
  }

  private RegistryValidationResponse validateScenarioMpacks(RegistryAdvisorRequest request)
      throws AmbariException {
    Registry registry = managementController.getRegistry(request.getRegistryId());
    Set<String> required = getScenarioMpacks(registry, request.getSelectedScenarios());
    List<RegistryValidationResult> results = new ArrayList<>();
    Map<String, MpackEntry> selected = loadSelectedEntries(
        registry, requireSelectedMpacks(request, "scenario validation"), results);

    for (String requiredName : required) {
      if (!selected.containsKey(requiredName)) {
        results.add(validation(SCENARIO_VALIDATION,
            "Selected mpacks do not contain " + requiredName
                + ", which is required by the selected scenarios."));
      }
    }
    validateDependencies(selected, results, COMPATIBILITY_VALIDATION);
    return validationResponse(request, results);
  }

  private RegistryValidationResponse validateUpgradeMpacks(RegistryAdvisorRequest request)
      throws AmbariException {
    Registry registry = managementController.getRegistry(request.getRegistryId());
    List<RegistryValidationResult> results = new ArrayList<>();
    Map<String, MpackEntry> selected = loadSelectedEntries(
        registry, requireSelectedMpacks(request, "upgrade validation"), results);
    validateDependencies(selected, results, UPGRADE_VALIDATION);
    return validationResponse(request, results);
  }

  private List<List<MpackEntry>> resolveBundles(Registry registry, Set<String> roots,
      Map<String, MpackEntry> fixed) throws AmbariException {
    if (roots.isEmpty()) {
      throw new AmbariException("At least one mpack is required for a recommendation");
    }
    if (roots.size() > MAX_MPACKS_PER_BUNDLE) {
      throw new AmbariException("A recommendation may contain at most "
          + MAX_MPACKS_PER_BUNDLE + " mpacks");
    }

    List<List<MpackEntry>> results = new ArrayList<>();
    SearchBudget budget = new SearchBudget();
    resolve(registry, new TreeSet<>(roots), new LinkedHashMap<>(), fixed,
        new HashMap<>(), results, budget);
    return results;
  }

  private void resolve(Registry registry, Set<String> required,
      Map<String, MpackEntry> assigned, Map<String, MpackEntry> fixed,
      Map<String, List<MpackEntry>> candidates, List<List<MpackEntry>> results,
      SearchBudget budget) throws AmbariException {
    if (results.size() == MAX_BUNDLES) {
      return;
    }
    if (++budget.states > MAX_SEARCH_STATES) {
      throw new AmbariException("Registry recommendation exceeded the bounded search limit of "
          + MAX_SEARCH_STATES + " states");
    }

    String nextName = null;
    for (String name : required) {
      if (!assigned.containsKey(name)) {
        nextName = name;
        break;
      }
    }
    if (nextName == null) {
      if (isCompatible(assigned)) {
        List<MpackEntry> bundle = new ArrayList<>(assigned.values());
        bundle.sort(Comparator.comparing(MpackEntry::getMpackName));
        results.add(bundle);
      }
      return;
    }

    List<MpackEntry> choices;
    MpackEntry fixedEntry = fixed.get(nextName);
    if (fixedEntry != null) {
      choices = Collections.singletonList(fixedEntry);
    } else {
      choices = candidates.get(nextName);
      if (choices == null) {
        choices = entriesFor(registry, nextName);
        candidates.put(nextName, choices);
      }
    }

    for (MpackEntry choice : choices) {
      if (!satisfiesAssignedConstraints(choice, assigned.values())) {
        continue;
      }
      assigned.put(nextName, choice);
      Set<String> expanded = new TreeSet<>(required);
      boolean candidateCompatible = true;
      for (RegistryMpackDependency dependency : choice.getRegistryMpackVersion().getDependencies()) {
        expanded.add(dependency.getName());
        MpackEntry dependencyEntry = assigned.get(dependency.getName());
        if (dependencyEntry != null && !satisfies(dependencyEntry, dependency)) {
          candidateCompatible = false;
          break;
        }
      }
      if (expanded.size() > MAX_MPACKS_PER_BUNDLE) {
        throw new AmbariException("A resolved recommendation may contain at most "
            + MAX_MPACKS_PER_BUNDLE + " mpacks");
      }
      if (candidateCompatible) {
        resolve(registry, expanded, assigned, fixed, candidates, results, budget);
      }
      assigned.remove(nextName);
      if (results.size() == MAX_BUNDLES) {
        return;
      }
    }
  }

  private boolean satisfiesAssignedConstraints(MpackEntry candidate,
      Collection<MpackEntry> assigned) throws AmbariException {
    for (MpackEntry entry : assigned) {
      for (RegistryMpackDependency dependency : entry.getRegistryMpackVersion().getDependencies()) {
        if (candidate.getMpackName().equals(dependency.getName())
            && !satisfies(candidate, dependency)) {
          return false;
        }
      }
    }
    return true;
  }

  private boolean isCompatible(Map<String, MpackEntry> entries) throws AmbariException {
    for (MpackEntry entry : entries.values()) {
      for (RegistryMpackDependency dependency : entry.getRegistryMpackVersion().getDependencies()) {
        MpackEntry dependencyEntry = entries.get(dependency.getName());
        if (dependencyEntry == null || !satisfies(dependencyEntry, dependency)) {
          return false;
        }
      }
    }
    return true;
  }

  private void validateDependencies(Map<String, MpackEntry> selected,
      List<RegistryValidationResult> results, String type) throws AmbariException {
    for (MpackEntry entry : selected.values()) {
      if (entry.getRegistryMpackVersion() == null) {
        continue;
      }
      for (RegistryMpackDependency dependency : entry.getRegistryMpackVersion().getDependencies()) {
        MpackEntry dependencyEntry = selected.get(dependency.getName());
        if (dependencyEntry == null) {
          results.add(validation(type, "Mpack " + entry.getMpackName() + "-"
              + entry.getMpackVersion() + " requires mpack " + dependency.getName() + "."));
        } else if (dependencyEntry.getRegistryMpackVersion() != null
            && !satisfies(dependencyEntry, dependency)) {
          results.add(validation(type, "Mpack " + entry.getMpackName() + "-"
              + entry.getMpackVersion() + " is incompatible with "
              + dependencyEntry.getMpackName() + "-" + dependencyEntry.getMpackVersion()
              + formatRange(dependency) + "."));
        }
      }
    }
  }

  private Map<String, MpackEntry> loadSelectedEntries(Registry registry,
      List<MpackEntry> requested, List<RegistryValidationResult> results) throws AmbariException {
    Map<String, MpackEntry> selected = new LinkedHashMap<>();
    for (MpackEntry entry : requested) {
      String name;
      try {
        name = requireName(entry);
      } catch (AmbariException e) {
        results.add(validation(UNKNOWN_VALIDATION, e.getMessage()));
        continue;
      }
      if (selected.containsKey(name)) {
        results.add(validation(UNKNOWN_VALIDATION,
            "Mpack " + name + " is selected more than once."));
        continue;
      }
      try {
        RegistryMpack registryMpack = registry.getRegistryMpack(name);
        RegistryMpackVersion version = registryMpack.getMpackVersion(entry.getMpackVersion());
        selected.put(name, createEntry(name, version));
      } catch (AmbariException | IllegalArgumentException e) {
        results.add(validation(UNKNOWN_VALIDATION, "Mpack " + name + "-"
            + entry.getMpackVersion() + " was not found in the registry."));
        selected.put(name, entry);
      }
    }
    return selected;
  }

  private Set<String> getScenarioMpacks(Registry registry,
      Collection<ScenarioEntry> selectedScenarios) throws AmbariException {
    if (selectedScenarios == null || selectedScenarios.isEmpty()) {
      throw new AmbariException("At least one scenario must be selected");
    }
    Set<String> names = new TreeSet<>();
    for (ScenarioEntry selectedScenario : selectedScenarios) {
      if (selectedScenario == null || StringUtils.isBlank(selectedScenario.getScenarioName())) {
        throw new AmbariException("Selected scenario name must not be empty");
      }
      RegistryScenario scenario = registry.getRegistryScenario(selectedScenario.getScenarioName());
      selectedScenario.setRegistryScenario(scenario);
      for (RegistryScenarioMpack mpack : scenario.getScenarioMpacks()) {
        names.add(mpack.getName());
      }
    }
    return names;
  }

  private List<MpackEntry> entriesFor(Registry registry, String name) throws AmbariException {
    RegistryMpack mpack = registry.getRegistryMpack(name);
    List<MpackEntry> entries = new ArrayList<>();
    for (RegistryMpackVersion version : sortedVersions(mpack)) {
      entries.add(createEntry(name, version));
    }
    if (entries.isEmpty()) {
      throw new AmbariException("Registry mpack " + name + " has no versions");
    }
    return entries;
  }

  private List<RegistryMpackVersion> sortedVersions(RegistryMpack mpack) throws AmbariException {
    List<RegistryMpackVersion> versions = new ArrayList<>(mpack.getMpackVersions());
    try {
      versions.sort((left, right) -> parseUnchecked(right.getMpackVersion())
          .compareTo(parseUnchecked(left.getMpackVersion())));
    } catch (IllegalArgumentException e) {
      throw new AmbariException("Registry mpack " + mpack.getMpackName()
          + " contains an invalid version", e);
    }
    return versions;
  }

  private boolean satisfies(MpackEntry entry, RegistryMpackDependency dependency)
      throws AmbariException {
    MpackVersion selected = parseVersion(entry.getMpackVersion(), entry.getMpackName());
    if (StringUtils.isNotBlank(dependency.getMinVersion())
        && selected.compareTo(parseVersion(dependency.getMinVersion(), dependency.getName())) < 0) {
      return false;
    }
    return StringUtils.isBlank(dependency.getMaxVersion())
        || selected.compareTo(parseVersion(dependency.getMaxVersion(), dependency.getName())) < 0;
  }

  private int compareVersions(String candidate, MpackVersion current, String name)
      throws AmbariException {
    return parseVersion(candidate, name).compareTo(current);
  }

  private MpackVersion parseVersion(String version, String name) throws AmbariException {
    try {
      return parseUnchecked(version);
    } catch (IllegalArgumentException e) {
      throw new AmbariException("Invalid version " + version + " for mpack " + name, e);
    }
  }

  private MpackVersion parseUnchecked(String version) {
    return MpackVersion.parse(version, false);
  }

  private MpackEntry createEntry(String name, RegistryMpackVersion version) {
    MpackEntry entry = new MpackEntry(name, version.getMpackVersion());
    entry.setRegistryMpackVersion(version);
    return entry;
  }

  private String requireName(MpackEntry entry) throws AmbariException {
    if (entry == null || StringUtils.isBlank(entry.getMpackName())
        || StringUtils.isBlank(entry.getMpackVersion())) {
      throw new AmbariException("Selected mpack name and version must not be empty");
    }
    return entry.getMpackName();
  }

  private List<MpackEntry> requireSelectedMpacks(RegistryAdvisorRequest request, String operation)
      throws AmbariException {
    if (request.getSelectedMpacks() == null || request.getSelectedMpacks().isEmpty()) {
      throw new AmbariException("At least one mpack must be selected for " + operation);
    }
    return request.getSelectedMpacks();
  }

  private void validateRequest(RegistryAdvisorRequest request) throws AmbariException {
    if (request == null || request.getRegistryId() == null || request.getRequestType() == null) {
      throw new AmbariException("Registry id and advisor request type are required");
    }
  }

  private RegistryRecommendationResponse recommendationResponse(RegistryAdvisorRequest request,
      List<List<MpackEntry>> bundles) {
    List<MpackBundle> ranked = new ArrayList<>();
    long rank = 1;
    for (List<MpackEntry> bundle : bundles) {
      ranked.add(new MpackBundle(rank++, bundle));
    }
    RegistryRecommendations recommendations = new RegistryRecommendations();
    recommendations.setMpackBundles(ranked);
    return RegistryRecommendationResponseBuilder.forRegistry(request.getRegistryId())
        .ofType(request.getRequestType())
        .forScenarios(request.getSelectedScenarios())
        .forMpacks(request.getSelectedMpacks())
        .withId(generateRequestId())
        .withRecommendations(recommendations)
        .build();
  }

  private RegistryValidationResponse validationResponse(RegistryAdvisorRequest request,
      List<RegistryValidationResult> results) {
    return RegistryValidationResponseBuilder.forRegistry(request.getRegistryId())
        .ofType(request.getRequestType())
        .forScenarios(request.getSelectedScenarios())
        .forMpacks(request.getSelectedMpacks())
        .withId(generateRequestId())
        .withValidations(results)
        .build();
  }

  private RegistryValidationResult validation(String type, String message) {
    return new RegistryValidationResult(type, FATAL, message);
  }

  private String formatRange(RegistryMpackDependency dependency) {
    StringBuilder range = new StringBuilder("; required range is ");
    range.append(StringUtils.isBlank(dependency.getMinVersion())
        ? "unbounded" : "[" + dependency.getMinVersion());
    range.append(',');
    range.append(StringUtils.isBlank(dependency.getMaxVersion())
        ? "unbounded" : dependency.getMaxVersion() + ")");
    return range.toString();
  }

  /**
   * Generates a process-local correlation id for advisor responses.
   */
  public long generateRequestId() {
    return requestId.incrementAndGet();
  }

  private static final class SearchBudget {
    private int states;
  }
}
