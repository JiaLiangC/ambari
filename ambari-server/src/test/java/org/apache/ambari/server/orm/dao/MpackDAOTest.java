/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ambari.server.orm.dao;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.List;

import org.apache.ambari.server.configuration.Configuration;
import org.apache.ambari.server.controller.ControllerModule;
import org.apache.ambari.server.orm.entities.MpackEntity;
import org.junit.Before;
import org.junit.Test;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.persist.PersistService;
import com.google.inject.persist.UnitOfWork;
import com.google.inject.persist.jpa.AmbariJpaPersistModule;


/**
 * Tests {@link MpackDAO}.
 */
public class MpackDAOTest {
  private Injector m_injector;
  private MpackDAO m_dao;

  @Before
  public void init() {
    java.util.Properties properties = new java.util.Properties();
    properties.setProperty(Configuration.SERVER_PERSISTENCE_TYPE.getKey(), "in-memory");
    Configuration configuration = new Configuration(properties);
    // Exercise real JPA transactions without initializing the entire controller.
    m_injector = Guice.createInjector(new AbstractModule() {
      @Override
      protected void configure() {
        bind(Configuration.class).toProvider(() -> configuration);
        install(new AmbariJpaPersistModule(Configuration.JDBC_UNIT_NAME)
            .properties(ControllerModule.getPersistenceProperties(configuration)));
      }
    });
    m_injector.getInstance(PersistService.class).start();
    m_injector.getInstance(UnitOfWork.class).begin();
    m_dao = m_injector.getInstance(MpackDAO.class);
  }

  @org.junit.After
  public void cleanup() throws Exception {
    if (m_injector != null) {
      org.apache.ambari.server.H2DatabaseCleaner.clearDatabaseAndStopPersistenceService(m_injector);
    }
  }

  @Test
  public void testCreateFind() {
    List<MpackEntity> eDefinitions = new ArrayList<>();

    // create 2 definitions
    for (int i = 1; i < 3; i++) {
      MpackEntity definition = new MpackEntity();
      definition.setId(new Long(100)+i);
      definition.setMpackName("testMpack" + i);
      definition.setRegistryId(Long.valueOf(i));
      definition.setMpackVersion("3.0.0.0-12"+i);
      definition.setMpackUri("http://c6401.ambari.apache.org:8080/resources/mpacks-repo/testMpack" + i + "-3.0.0.0-123.tar.gz");
      eDefinitions.add(definition);
      m_dao.create(definition);
    }

    List<MpackEntity> definitions = m_dao.findAll();
    assertNotNull(definitions);
    assertEquals(2, definitions.size());
    definitions = m_dao.findByNameVersion("testMpack1","3.0.0.0-121");
    assertEquals(1, definitions.size());
    assertEquals(new Long(101),(Long)definitions.get(0).getId());
    MpackEntity entity = m_dao.findById(new Long(102));
    assertEquals(entity.getMpackName(),"testMpack2");
    assertEquals(entity.getMpackVersion(),"3.0.0.0-122");

  }
  @Test
  public void testCatalogDeleteRollsBackWhileBlueprintReferencesStack() throws Exception {
    MpackEntity entity = new MpackEntity();
    entity.setMpackName("FK_PACKAGE");
    entity.setMpackVersion("1");
    entity.setMpackUri("file:///fixture/mpack.json");
    Long id = m_dao.create(entity);
    org.apache.ambari.server.orm.entities.StackEntity stack = new org.apache.ambari.server.orm.entities.StackEntity();
    stack.setStackName("FK_PACKAGE");
    stack.setStackVersion("1");
    stack.setMpackId(id);
    StackDAO stacks = m_injector.getInstance(StackDAO.class);
    stacks.create(stack);
    org.apache.ambari.server.orm.entities.BlueprintEntity blueprint = new org.apache.ambari.server.orm.entities.BlueprintEntity();
    blueprint.setBlueprintName("protected");
    blueprint.setStack(stack);
    BlueprintDAO blueprints = m_injector.getInstance(BlueprintDAO.class);
    blueprints.create(blueprint);
    org.junit.Assert.assertThrows(RuntimeException.class, () -> m_dao.removeCatalog(id));
    assertNotNull(m_dao.findById(id));
    assertNotNull(stacks.find("FK_PACKAGE", "1"));
    blueprints.removeByName("protected");
    m_dao.removeCatalog(id);
    org.junit.Assert.assertNull(m_dao.findById(id));
    org.apache.ambari.server.orm.entities.BlueprintEntity stale = new org.apache.ambari.server.orm.entities.BlueprintEntity();
    stale.setBlueprintName("stale-reference");
    stale.setStack(stack);
    org.junit.Assert.assertThrows(RuntimeException.class, () -> blueprints.create(stale));
    org.junit.Assert.assertNull(blueprints.findByName("stale-reference"));
  }

  @Test
  public void testRemovedCatalogCannotBeReusedByRepositoryOrCluster() throws Exception {
    MpackEntity pack = new MpackEntity();
    pack.setMpackName("REMOVED_PACKAGE");
    pack.setMpackVersion("1");
    pack.setMpackUri("file:///fixture/mpack.json");
    Long id = m_dao.create(pack);
    org.apache.ambari.server.orm.entities.StackEntity stack = new org.apache.ambari.server.orm.entities.StackEntity();
    stack.setStackName("REMOVED_PACKAGE");
    stack.setStackVersion("1");
    stack.setMpackId(id);
    StackDAO stacks = m_injector.getInstance(StackDAO.class);
    stacks.create(stack);
    RepositoryVersionDAO repositories = m_injector.getInstance(RepositoryVersionDAO.class);
    org.apache.ambari.server.orm.entities.RepositoryVersionEntity repository = new org.apache.ambari.server.orm.entities.RepositoryVersionEntity();
    repository.setStack(stack);
    repository.setVersion("1");
    repository.setDisplayName("host fixture");
    repositories.create(repository);
    Long repositoryId = repository.getId();
    m_dao.removeCatalog(id);
    org.junit.Assert.assertNull(stacks.findById(stack.getStackId()));
    org.junit.Assert.assertNull(repositories.findByPK(repositoryId));
    org.junit.Assert.assertThrows(RuntimeException.class, () -> repositories.create(repository));
    org.junit.Assert.assertThrows(RuntimeException.class, () -> repositories.merge(repository));
    org.apache.ambari.server.orm.entities.ClusterEntity cluster = new org.apache.ambari.server.orm.entities.ClusterEntity();
    cluster.setClusterName("stale-target");
    cluster.setDesiredStack(stack);
    org.junit.Assert.assertThrows(RuntimeException.class, () -> m_injector.getInstance(ClusterDAO.class).create(cluster));
  }

  @Test
  public void testServiceTargetIncarnationSurvivesMergeButNotRecreation() throws Exception {
    jakarta.persistence.EntityManager manager = m_injector.getInstance(jakarta.persistence.EntityManager.class);
    manager.getTransaction().begin();
    org.apache.ambari.server.orm.entities.StackEntity stack = new org.apache.ambari.server.orm.entities.StackEntity();
    stack.setStackName("HOST");
    stack.setStackVersion("1");
    manager.persist(stack);
    org.apache.ambari.server.orm.entities.ResourceTypeEntity type = new org.apache.ambari.server.orm.entities.ResourceTypeEntity();
    type.setId(org.apache.ambari.server.security.authorization.ResourceType.CLUSTER.getId());
    type.setName("CLUSTER");
    manager.persist(type);
    org.apache.ambari.server.orm.entities.ResourceEntity resource = new org.apache.ambari.server.orm.entities.ResourceEntity();
    resource.setResourceType(type);
    org.apache.ambari.server.orm.entities.ClusterEntity cluster = new org.apache.ambari.server.orm.entities.ClusterEntity();
    cluster.setClusterName("host-scope");
    cluster.setDesiredStack(stack);
    cluster.setResource(resource);
    manager.persist(cluster);
    manager.getTransaction().commit();
    Long clusterId = cluster.getClusterId();
    ClusterDAO clusters = m_injector.getInstance(ClusterDAO.class);
    ClusterServiceDAO services = m_injector.getInstance(ClusterServiceDAO.class);
    org.apache.ambari.server.orm.entities.ClusterServiceEntity service =
        new org.apache.ambari.server.orm.entities.ClusterServiceEntity();
    service.setClusterEntity(clusters.findById(clusterId));
    service.setClusterId(clusterId);
    service.setServiceName("HTTP_ECHO");
    services.create(service);
    String first = services.getOrCreateMpackTargetIncarnation(clusterId, "HTTP_ECHO");
    assertNotNull(java.util.UUID.fromString(first));
    service.setMpackTargetIncarnation(null);
    services.merge(service);
    assertEquals(first, services.getOrCreateMpackTargetIncarnation(clusterId, "HTTP_ECHO"));
    services.remove(service);
    org.apache.ambari.server.orm.entities.ClusterServiceEntity replacement =
        new org.apache.ambari.server.orm.entities.ClusterServiceEntity();
    replacement.setClusterEntity(clusters.findById(clusterId));
    replacement.setClusterId(clusterId);
    replacement.setServiceName("HTTP_ECHO");
    services.create(replacement);
    org.junit.Assert.assertNotEquals(first, services.getOrCreateMpackTargetIncarnation(clusterId, "HTTP_ECHO"));
    org.junit.Assert.assertThrows(IllegalArgumentException.class,
        () -> services.getOrCreateMpackTargetIncarnation(clusterId, "UNASSIGNED"));
  }

  @Test
  public void testConcurrentBlueprintCommitPreventsCatalogRemoval() throws Exception {
    MpackEntity pack = new MpackEntity();
    pack.setMpackName("CONCURRENT_PACKAGE");
    pack.setMpackVersion("1");
    pack.setMpackUri("file:///fixture/mpack.json");
    Long id = m_dao.create(pack);
    org.apache.ambari.server.orm.entities.StackEntity stack = new org.apache.ambari.server.orm.entities.StackEntity();
    stack.setStackName("CONCURRENT_PACKAGE");
    stack.setStackVersion("1");
    stack.setMpackId(id);
    m_injector.getInstance(StackDAO.class).create(stack);
    jakarta.persistence.EntityManager manager = m_injector.getInstance(jakarta.persistence.EntityManager.class);
    java.util.concurrent.ExecutorService worker = java.util.concurrent.Executors.newSingleThreadExecutor();
    try {
      manager.getTransaction().begin();
      org.apache.ambari.server.orm.entities.BlueprintEntity blueprint = new org.apache.ambari.server.orm.entities.BlueprintEntity();
      blueprint.setBlueprintName("concurrent-reference");
      blueprint.setStack(stack);
      m_injector.getInstance(BlueprintDAO.class).create(blueprint);
      manager.flush();
      java.util.concurrent.Future<RuntimeException> deletion = worker.submit(() -> {
        UnitOfWork work = m_injector.getInstance(UnitOfWork.class);
        work.begin();
        try {
          m_dao.removeCatalog(id);
          return null;
        } catch (RuntimeException expected) {
          return expected;
        } finally {
          work.end();
        }
      });
      try {
        assertNotNull(deletion.get(150, java.util.concurrent.TimeUnit.MILLISECONDS));
      } catch (java.util.concurrent.TimeoutException expected) {
        // Both an early safe rejection and waiting for the reference are valid.
      }
      manager.getTransaction().commit();
      assertNotNull(deletion.get(10, java.util.concurrent.TimeUnit.SECONDS));
      assertNotNull(m_dao.findById(id));
    } finally {
      if (manager.getTransaction().isActive()) {
        manager.getTransaction().rollback();
      }
      worker.shutdownNow();
    }
  }

  @Test
  public void testFailedUpgradeKeepsConfirmedCatalogReferenceAndLateResponsesCannotReplaceIt() {
    MpackEntity previous = release("1", "a".repeat(64));
    MpackEntity candidate = release("2", "b".repeat(64));
    MpackTargetResourceDAO resources = m_injector.getInstance(MpackTargetResourceDAO.class);
    com.google.gson.JsonObject binding = releaseBinding(previous, "host-one", "STOP");
    resources.recordIntent(binding.toString(), 200L);
    resources.recordReport(200L, stoppedReport(binding, 200L, previous.getContentDigest()));
    assertEquals(previous.getId(), resources.requireStoppedRelease(9L, "HTTP_ECHO", binding.get("targetIncarnation").getAsString()));

    binding.addProperty("operation", "UPGRADE");
    binding.addProperty("packageId", candidate.getId());
    binding.addProperty("packageDigest", candidate.getContentDigest());
    resources.recordIntent(binding.toString(), 201L);
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> m_dao.removeCatalog(previous.getId()));
    org.junit.Assert.assertThrows(IllegalStateException.class,
        () -> resources.requireStoppedRelease(9L, "HTTP_ECHO", binding.get("targetIncarnation").getAsString()));
    assertEquals(previous.getId(), resources.findByCluster(9L).get(0).getMaterializedMpackId());

    // STOP can resolve native uncertainty without claiming that new artifacts were installed.
    binding.addProperty("operation", "STOP");
    resources.recordIntent(binding.toString(), 202L);
    resources.recordReport(202L, stoppedReport(binding, 202L, previous.getContentDigest()));
    assertEquals(previous.getId(), resources.requireStoppedRelease(9L, "HTTP_ECHO", binding.get("targetIncarnation").getAsString()));
    resources.recordReport(201L, stoppedReport(binding, 201L, candidate.getContentDigest()));
    assertEquals(previous.getId(), resources.findByCluster(9L).get(0).getMaterializedMpackId());

    binding.addProperty("operation", "UPGRADE");
    resources.recordIntent(binding.toString(), 203L);
    resources.recordReport(203L, stoppedReport(binding, 203L, candidate.getContentDigest()));
    assertEquals(candidate.getId(), resources.requireStoppedRelease(9L, "HTTP_ECHO", binding.get("targetIncarnation").getAsString()));
    m_dao.removeCatalog(previous.getId());
    org.junit.Assert.assertNull(m_dao.findById(previous.getId()));
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> m_dao.removeCatalog(candidate.getId()));
  }

  @Test
  public void testDetachedOwnershipMustBeReclaimedBeforeMutationAndSurvivesCatalogRemoval() {
    MpackEntity pack = release("1", "a".repeat(64));
    MpackTargetResourceDAO resources = m_injector.getInstance(MpackTargetResourceDAO.class);
    com.google.gson.JsonObject binding = releaseBinding(pack, "host-one", "ADOPT");
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.recordIntent(binding.toString(), 300L));
    binding.addProperty("operation", "STOP");
    resources.recordIntent(binding.toString(), 300L);
    resources.recordReport(300L, stoppedReport(binding, 300L, pack.getContentDigest()));
    binding.addProperty("operation", "DETACH");
    resources.recordIntent(binding.toString(), 301L);
    binding.addProperty("operation", "START");
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.recordIntent(binding.toString(), 302L));
    com.google.gson.JsonObject report = com.google.gson.JsonParser.parseString(stoppedReport(binding, 301L, pack.getContentDigest())).getAsJsonObject();
    com.google.gson.JsonObject operation = report.getAsJsonObject("mpackOperation");
    operation.addProperty("detached", true);
    operation.add("retainedResources", com.google.gson.JsonParser.parseString("[{\"path\":\"/fixture/owned\",\"device\":1,\"inode\":2}]"));
    resources.recordReport(301L, report.toString());
    assertEquals("DETACHED", resources.findByCluster(9L).get(0).getResourceState());
    resources.requireRemovable(9L, "HTTP_ECHO");
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.recordIntent(binding.toString(), 302L));
    binding.addProperty("operation", "ADOPT");
    resources.recordIntent(binding.toString(), 302L);
    operation.addProperty("taskId", "302");
    operation.addProperty("detached", false);
    resources.recordReport(302L, report.toString());
    assertEquals("MANAGED", resources.findByCluster(9L).get(0).getResourceState());
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> m_dao.removeCatalog(pack.getId()));
    binding.addProperty("operation", "DETACH");
    resources.recordIntent(binding.toString(), 303L);
    operation.addProperty("taskId", "303");
    operation.addProperty("detached", true);
    resources.recordReport(303L, report.toString());
    m_dao.removeCatalog(pack.getId());
    org.junit.Assert.assertNull(resources.findByCluster(9L).get(0).getMpackId());
    assertEquals("DETACHED", resources.findByCluster(9L).get(0).getResourceState());
  }

  @Test
  public void testMixedConfirmedReleasesCannotSelectAnotherPackage() {
    MpackEntity previous = release("1", "a".repeat(64));
    MpackEntity candidate = release("2", "b".repeat(64));
    MpackTargetResourceDAO resources = m_injector.getInstance(MpackTargetResourceDAO.class);
    com.google.gson.JsonObject first = releaseBinding(previous, "host-one", "STOP");
    com.google.gson.JsonObject second = releaseBinding(candidate, "host-two", "STOP");
    resources.recordIntent(first.toString(), 210L);
    resources.recordReport(210L, stoppedReport(first, 210L, previous.getContentDigest()));
    resources.recordIntent(second.toString(), 211L);
    resources.recordReport(211L, stoppedReport(second, 211L, candidate.getContentDigest()));
    org.junit.Assert.assertThrows(IllegalStateException.class,
        () -> resources.requireStoppedRelease(9L, "HTTP_ECHO", first.get("targetIncarnation").getAsString()));
  }

  private MpackEntity release(String version, String digest) {
    MpackEntity pack = new MpackEntity();
    pack.setMpackName("UPGRADE_PACKAGE");
    pack.setMpackVersion(version);
    pack.setMpackUri("file:///fixture/mpack.json");
    pack.setContentDigest(digest);
    m_dao.create(pack);
    return pack;
  }

  private com.google.gson.JsonObject releaseBinding(MpackEntity pack, String host, String operation) {
    com.google.gson.JsonObject binding = new com.google.gson.JsonObject();
    binding.addProperty("packageId", pack.getId());
    binding.addProperty("packageDigest", pack.getContentDigest());
    binding.addProperty("clusterId", 9);
    binding.addProperty("serviceName", "HTTP_ECHO");
    binding.addProperty("targetIncarnation", "00000000-0000-0000-0000-000000000009");
    binding.addProperty("hostName", host);
    binding.addProperty("role", "HTTP_ECHO_SERVER");
    binding.addProperty("operation", operation);
    return binding;
  }

  private String stoppedReport(com.google.gson.JsonObject binding, Long task, String materializedDigest) {
    com.google.gson.JsonObject identity = binding.deepCopy();
    identity.addProperty("componentName", "HTTP_ECHO_SERVER");
    com.google.gson.JsonObject observation = new com.google.gson.JsonObject();
    observation.add("identity", identity);
    observation.addProperty("loadState", "loaded");
    observation.addProperty("state", "inactive");
    observation.addProperty("pid", "0");
    com.google.gson.JsonObject outcome = new com.google.gson.JsonObject();
    outcome.addProperty("state", "SUCCEEDED");
    outcome.addProperty("taskId", task.toString());
    outcome.add("packageDigest", binding.get("packageDigest"));
    outcome.addProperty("materializedPackageDigest", materializedDigest);
    outcome.add("observation", observation);
    com.google.gson.JsonObject report = new com.google.gson.JsonObject();
    report.add("mpackOperation", outcome);
    return report.toString();
  }

  @Test
  public void testDefaultRepositorySelectionAndDurableUninstallEvidence() {
    MpackEntity pack = new MpackEntity();
    pack.setMpackName("RESOURCE_PACKAGE");
    pack.setMpackVersion("1");
    pack.setMpackUri("file:///fixture/mpack.json");
    pack.setContentDigest("a".repeat(64));
    Long id = m_dao.create(pack);
    org.apache.ambari.server.orm.entities.StackEntity stack = new org.apache.ambari.server.orm.entities.StackEntity();
    stack.setStackName("RESOURCE_PACKAGE");
    stack.setStackVersion("1");
    stack.setMpackId(id);
    m_injector.getInstance(StackDAO.class).create(stack);
    Long repository = m_dao.ensureDefaultRepository(id);
    assertEquals(repository, m_dao.ensureDefaultRepository(id));
    assertEquals(id, m_injector.getInstance(RepositoryVersionDAO.class).findByPK(repository).getStack().getMpackId());

    MpackTargetResourceDAO resources = m_injector.getInstance(MpackTargetResourceDAO.class);
    com.google.gson.JsonObject binding = new com.google.gson.JsonObject();
    binding.addProperty("packageId", id);
    binding.addProperty("packageDigest", pack.getContentDigest());
    binding.addProperty("clusterId", 7);
    binding.addProperty("serviceName", "HTTP_ECHO");
    binding.addProperty("targetIncarnation", "00000000-0000-0000-0000-000000000007");
    binding.addProperty("hostName", "host.example");
    binding.addProperty("role", "HTTP_ECHO_SERVER");
    binding.addProperty("operation", "INSTALL");
    resources.recordIntent(binding.toString(), 100L);
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.requireRemovable(7L, "HTTP_ECHO"));
    binding.addProperty("operation", "UNINSTALL");
    resources.recordIntent(binding.toString(), 101L);
    com.google.gson.JsonObject identity = binding.deepCopy();
    identity.addProperty("componentName", "HTTP_ECHO_SERVER");
    com.google.gson.JsonObject observation = new com.google.gson.JsonObject();
    observation.add("identity", identity);
    observation.addProperty("loadState", "not-found");
    observation.addProperty("state", "inactive");
    observation.addProperty("pid", "0");
    com.google.gson.JsonObject outcome = new com.google.gson.JsonObject();
    outcome.addProperty("state", "SUCCEEDED");
    outcome.addProperty("taskId", "101");
    outcome.addProperty("packageDigest", pack.getContentDigest());
    outcome.addProperty("materializedPackageDigest", pack.getContentDigest());
    outcome.add("observation", observation);
    outcome.add("retainedResources", new com.google.gson.JsonArray());
    com.google.gson.JsonObject report = new com.google.gson.JsonObject();
    report.add("mpackOperation", outcome);
    resources.recordReport(101L, report.toString());
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.requireRemovable(7L, "HTTP_ECHO"));
    com.google.gson.JsonObject retainedRoot = new com.google.gson.JsonObject();
    retainedRoot.addProperty("path", "/fixture/owned");
    retainedRoot.addProperty("device", 1);
    retainedRoot.addProperty("inode", 2);
    outcome.getAsJsonArray("retainedResources").add(retainedRoot);
    resources.recordReport(100L, report.toString());
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.requireRemovable(7L, "HTTP_ECHO"));
    identity.addProperty("targetIncarnation", "00000000-0000-0000-0000-000000000008");
    resources.recordReport(101L, report.toString());
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.requireRemovable(7L, "HTTP_ECHO"));
    identity.add("targetIncarnation", binding.get("targetIncarnation"));
    resources.recordReport(101L, report.toString());
    resources.requireRemovable(7L, "HTTP_ECHO");
    // No task/service FK: evidence remains valid after normal history retention.
    m_injector.getInstance(jakarta.persistence.EntityManager.class).clear();
    assertEquals("UNINSTALLED_RETAINED", resources.findByCluster(7L).get(0).getResourceState());
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> m_dao.removeCatalog(id));
    assertNotNull(m_dao.findById(id));
    binding.addProperty("operation", "PURGE");
    resources.recordIntent(binding.toString(), 102L);
    binding.addProperty("operation", "STOP");
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.recordIntent(binding.toString(), 103L));
    binding.addProperty("operation", "PURGE");
    assertEquals(102L, resources.findByCluster(7L).get(0).getTaskId().longValue());
    outcome.addProperty("taskId", "102");
    resources.recordReport(102L, report.toString());
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.requireRemovable(7L, "HTTP_ECHO"));
    outcome.addProperty("purged", true);
    outcome.add("purgedResources", new com.google.gson.JsonArray());
    resources.recordReport(102L, report.toString());
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.requireRemovable(7L, "HTTP_ECHO"));
    com.google.gson.JsonObject purgedRoot = retainedRoot.deepCopy();
    purgedRoot.addProperty("disposition", "receipt-only");
    outcome.getAsJsonArray("purgedResources").add(purgedRoot);
    resources.recordReport(102L, report.toString());
    resources.requireRemovable(7L, "HTTP_ECHO");
    binding.addProperty("operation", "START");
    org.junit.Assert.assertThrows(IllegalStateException.class, () -> resources.recordIntent(binding.toString(), 103L));
    org.apache.ambari.server.orm.entities.MpackTargetResourceEntity held = resources.findByCluster(7L).get(0);
    m_dao.removeCatalog(id);
    org.junit.Assert.assertNull(held.getMpackId());
    m_injector.getInstance(jakarta.persistence.EntityManager.class).clear();
    assertEquals("PURGED", resources.findByCluster(7L).get(0).getResourceState());
    org.junit.Assert.assertNull(resources.findByCluster(7L).get(0).getMpackId());
    assertNotNull(resources.findByCluster(7L).get(0).getTaskBinding());
  }

}
