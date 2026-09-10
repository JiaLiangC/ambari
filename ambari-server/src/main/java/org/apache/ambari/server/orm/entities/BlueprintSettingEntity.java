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

package org.apache.ambari.server.orm.entities;

import java.util.List;
import java.util.Map;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.TableGenerator;
import jakarta.persistence.UniqueConstraint;

import org.apache.ambari.server.topology.MpackReference;

import com.google.gson.Gson;

/**
 * Represents a blueprint setting.
 */
@Table(name = "blueprint_setting", uniqueConstraints =
@UniqueConstraint(
        name = "UQ_blueprint_setting_name", columnNames = {"blueprint_name", "setting_name"}
  )
)

@TableGenerator(name = "blueprint_setting_id_generator",
        table = "ambari_sequences", pkColumnName = "sequence_name", valueColumnName = "sequence_value",
        pkColumnValue = "blueprint_setting_id_seq", initialValue = 0)

@Entity
public class BlueprintSettingEntity {

  @Id
  @Column(name = "id", nullable = false, insertable = true, updatable = false)
  @GeneratedValue(strategy = GenerationType.TABLE, generator = "blueprint_setting_id_generator")
  private long id;

  @Column(name = "blueprint_name", nullable = false, insertable = false, updatable = false)
  private String blueprintName;

  @Column(name = "setting_name", nullable = false, insertable = true, updatable = false)
  private String settingName;

  @Column(name = "setting_data", nullable = false, insertable = true, updatable = false)
  @Basic(fetch = FetchType.LAZY)
  @Lob
  private String settingData;

  @ManyToOne
  @JoinColumn(name = "blueprint_name", referencedColumnName = "blueprint_name", nullable = false)
  private BlueprintEntity blueprint;

  /**
   * Get the blueprint entity instance.
   *
   * @return blueprint entity
   */
  public BlueprintEntity getBlueprintEntity() {
    return blueprint;
  }

  /**
   * Set the blueprint entity instance.
   *
   * @param entity  blueprint entity
   */
  public void setBlueprintEntity(BlueprintEntity entity) {
    this.blueprint = entity;
  }

  /**
   * Get the name of the associated blueprint.
   *
   * @return blueprint name
   */
  public String getBlueprintName() {
    return blueprintName;
  }

  /**
   * Set the name of the associated blueprint.
   * '
   * @param blueprintName  blueprint name
   */
  public void setBlueprintName(String blueprintName) {
    this.blueprintName = blueprintName;
  }

  /**
   * Get the setting name.
   *
   * @return setting name
   */
  public String getSettingName() {
    return settingName;
  }

  /**
   * Set the setting name.
   *
   * @param settingName  setting name
   */
  public void setSettingName(String settingName) {
    this.settingName = settingName;
  }

  /**
   * Get the setting data.
   *
   * @return setting data in json format
   */
  public String getSettingData() {
    return settingData;
  }

  /**
   * Set the setting data.
   *
   * @param settingData  all config data in json format
   */
  public void setSettingData(String settingData) {
    this.settingData = settingData;
  }
  /** Keep package settings within the existing Blueprint stack foreign key. */
  @PrePersist
  @PreUpdate
  void validatePackageReferenceScope() {
    if (!MpackReference.SETTING_NAME.equals(settingName)) {
      return;
    }
    if (blueprint == null || blueprint.getStack() == null) {
      throw new IllegalArgumentException("Package references require a Blueprint stack");
    }
    List<Map<String, String>> references = new Gson().fromJson(settingData, List.class);
    if (references == null) {
      throw new IllegalArgumentException("Invalid package reference setting");
    }
    StackEntity stack = blueprint.getStack();
    for (Map<String, String> value : references) {
      for (String field : List.of("owner", "lifecycle_state", "generation", "retention_until")) {
        if (value.containsKey(field)) {
          throw new IllegalArgumentException("Blueprint settings cannot assert live deployment state");
        }
      }
      MpackReference reference = MpackReference.fromSettingMap(value);
      if (stack.getMpackId() == null || !stack.getMpackId().equals(reference.getMpackId())
          || !stack.getStackName().equals(reference.getMpackName())
          || !stack.getStackVersion().equals(reference.getVersion())) {
        throw new IllegalArgumentException("Package references must match the Blueprint stack");
      }
    }
  }

}
