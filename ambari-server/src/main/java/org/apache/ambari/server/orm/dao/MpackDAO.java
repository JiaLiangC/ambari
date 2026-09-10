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

import java.util.List;
import java.util.Map;

import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.TypedQuery;

import org.apache.ambari.server.orm.RequiresSession;
import org.apache.ambari.server.orm.entities.BlueprintSettingEntity;
import org.apache.ambari.server.orm.entities.MpackEntity;
import org.apache.ambari.server.orm.entities.MpackTargetResourceEntity;
import org.apache.ambari.server.orm.entities.RepositoryVersionEntity;
import org.apache.ambari.server.orm.entities.StackEntity;
import org.apache.ambari.server.topology.MpackReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import com.google.inject.persist.Transactional;

@Singleton
public class MpackDAO {
  protected final static Logger LOG = LoggerFactory.getLogger(MpackDAO.class);

  /**
   * JPA entity manager
   */
  @Inject
  Provider<EntityManager> m_entityManagerProvider;

  /**
   * DAO utilities for dealing mostly with {@link TypedQuery} results.
   */
  @Inject
  private DaoUtils m_daoUtils;

  /**
   * Persists a new mpack
   */
  @Transactional
  public Long create(MpackEntity mpackEntity) {
    m_entityManagerProvider.get().persist(mpackEntity);
    return mpackEntity.getId();
  }

  /** Give authenticated definitions a selectable repository using the existing service FK. */
  @Transactional
  public Long ensureDefaultRepository(Long mpackId) {
    EntityManager manager = m_entityManagerProvider.get();
    MpackEntity pack = manager.find(MpackEntity.class, mpackId, LockModeType.PESSIMISTIC_WRITE);
    if (pack == null || pack.getContentDigest() == null) {
      throw new IllegalStateException("A registered authored package is required");
    }
    StackEntity stack = manager.createQuery("SELECT s FROM StackEntity s WHERE s.mpackId = :id", StackEntity.class)
        .setParameter("id", mpackId).getSingleResult();
    String projection = "MPACK_" + org.apache.commons.codec.digest.DigestUtils.sha256Hex(pack.getMpackName());
    if (!projection.equals(stack.getStackName())) {
      // Preserve the Stack PK and all repository/config/service FKs. Only the
      // compatibility name changes; authored names could not round-trip StackId.
      stack.setStackName(projection);
      manager.flush();
    }
    List<RepositoryVersionEntity> repositories = manager.createQuery(
        "SELECT r FROM RepositoryVersionEntity r WHERE r.stack = :stack AND r.version = :version",
        RepositoryVersionEntity.class).setParameter("stack", stack)
        .setParameter("version", pack.getMpackVersion()).getResultList();
    if (!repositories.isEmpty()) {
      return repositories.get(0).getId();
    }
    // This selects immutable service definitions. Declared host OS packages continue
    // to use existing host repositories; no fictitious OS download URL is created.
    RepositoryVersionEntity repository = new RepositoryVersionEntity(stack, pack.getMpackVersion(),
        pack.getMpackName() + "-" + pack.getMpackVersion(), java.util.Collections.emptyList());
    manager.persist(repository);
    return repository.getId();
  }

  /**
   * Gets an mpack with the specified ID.
   *
   * @param id
   *          the ID of the mpack to retrieve.
   * @return the mpack or {@code null} if none exists.
   */
  @RequiresSession
  public MpackEntity findById(long id) {
    return m_entityManagerProvider.get().find(MpackEntity.class, id);
  }

  /**
   * Gets mpacks with specified mpack name and mpack version.
   *
   * @param mpackName
   * @param mpackVersion
   * @return the mpack or {@code null} if none exists.
   */
  @RequiresSession
  public List<MpackEntity> findByNameVersion(String mpackName, String mpackVersion) {
    TypedQuery<MpackEntity> query = m_entityManagerProvider.get().createNamedQuery("MpackEntity.findByNameVersion", MpackEntity.class);
    query.setParameter("mpackName", mpackName);
    query.setParameter("mpackVersion", mpackVersion);
    return m_daoUtils.selectList(query);
  }

  /**
   * Gets all mpacks stored in the database across all clusters.
   *
   * @return all mpacks or an empty list if none exist (never {@code null}).
   */
  @RequiresSession
  public List<MpackEntity> findAll() {
    TypedQuery<MpackEntity> query = m_entityManagerProvider.get().createNamedQuery(
            "MpackEntity.findAll", MpackEntity.class);
    return m_daoUtils.selectList(query);
  }

  @RequiresSession
  public List<MpackEntity> findByRegistryId(Long registryId) {
    TypedQuery<MpackEntity> query = m_entityManagerProvider.get().createNamedQuery(
        "MpackEntity.findByRegistryId", MpackEntity.class);
    query.setParameter("registryId", registryId);
    return m_daoUtils.selectList(query);
  }

  @Transactional
  public void removeById(Long id) {
    m_entityManagerProvider.get().remove(findById(id));
  }

  /**
   * Delete catalog rows atomically. Existing stack/repository foreign keys guard
   * concurrent cluster, service and Blueprint references. New Blueprint package
   * settings are constrained to their stack by BlueprintSettingEntity. Historical settings
   * are checked here before any bulk delete; no filesystem mutation occurs here.
   */
  @Transactional
  public void removeCatalog(Long id) {
    EntityManager entityManager = m_entityManagerProvider.get();
    MpackEntity entity = entityManager.find(MpackEntity.class, id, LockModeType.PESSIMISTIC_WRITE);
    if (entity == null) {
      return;
    }
    Long retained = entityManager.createQuery("SELECT COUNT(r) FROM MpackTargetResourceEntity r WHERE (r.mpackId = :id OR r.materializedMpackId = :id) AND r.resourceState NOT IN ('PURGED', 'DETACHED')",
        Long.class).setParameter("id", id).getSingleResult();
    if (retained != 0) {
      throw new IllegalStateException("Managed or retained resources reference this mpack");
    }
    // Update managed entities so callers holding a retention row cannot flush a stale FK.
    // The package lock prevents any new intent from acquiring a reference during deletion.
    while (true) {
      List<MpackTargetResourceEntity> purged = entityManager.createQuery(
          "SELECT r FROM MpackTargetResourceEntity r WHERE (r.mpackId = :id OR r.materializedMpackId = :id) AND r.resourceState IN ('PURGED', 'DETACHED') ORDER BY r.targetKey",
          MpackTargetResourceEntity.class).setParameter("id", id).setMaxResults(256).getResultList();
      if (purged.isEmpty()) {
        break;
      }
      purged.forEach(resource -> {
        if (id.equals(resource.getMpackId())) { resource.setMpackId(null); }
        if (id.equals(resource.getMaterializedMpackId())) { resource.setMaterializedMpackId(null); }
      });
      entityManager.flush();
    }
    List<BlueprintSettingEntity> settings = entityManager.createQuery(
        "SELECT s FROM BlueprintSettingEntity s WHERE s.settingName = :name", BlueprintSettingEntity.class)
        .setParameter("name", MpackReference.SETTING_NAME).getResultList();
    for (BlueprintSettingEntity setting : settings) {
      List<Map<String, String>> references = new Gson().fromJson(setting.getSettingData(), List.class);
      if (references == null) {
        throw new IllegalStateException("Invalid Blueprint package references block deletion");
      }
      for (Map<String, String> reference : references) {
        if (id.equals(MpackReference.fromSettingMap(reference).getMpackId())) {
          throw new IllegalStateException("Blueprint references this mpack");
        }
      }
    }
    List<org.apache.ambari.server.orm.entities.StackEntity> stacks = entityManager.createQuery(
        "SELECT s FROM StackEntity s WHERE s.mpackId = :id", org.apache.ambari.server.orm.entities.StackEntity.class)
        .setParameter("id", id).getResultList();
    List<org.apache.ambari.server.orm.entities.RepositoryVersionEntity> repositories = entityManager.createQuery(
        "SELECT r FROM RepositoryVersionEntity r WHERE r.stack.mpackId = :id",
        org.apache.ambari.server.orm.entities.RepositoryVersionEntity.class).setParameter("id", id).getResultList();
    entityManager.flush();
    entityManager.createNativeQuery("DELETE FROM repo_version WHERE stack_id IN "
        + "(SELECT stack_id FROM stack WHERE mpack_id = ?)").setParameter(1, id).executeUpdate();
    entityManager.createNativeQuery("DELETE FROM stack WHERE mpack_id = ?")
        .setParameter(1, id).executeUpdate();
    entityManager.remove(entity);
    entityManager.flush();
    // Native deletes bypass JPA identity maps. Do not expose removed projections.
    stacks.forEach(entityManager::detach);
    repositories.forEach(entityManager::detach);
    entityManager.getEntityManagerFactory().getCache().evict(org.apache.ambari.server.orm.entities.StackEntity.class);
    entityManager.getEntityManagerFactory().getCache().evict(org.apache.ambari.server.orm.entities.RepositoryVersionEntity.class);
    entityManager.getEntityManagerFactory().getCache().evict(org.apache.ambari.server.orm.entities.MpackTargetResourceEntity.class);
  }

}
