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

}
