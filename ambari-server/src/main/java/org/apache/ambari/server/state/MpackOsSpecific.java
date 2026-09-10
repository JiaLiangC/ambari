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
package org.apache.ambari.server.state;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.google.gson.annotations.SerializedName;

/**
 * Operating-system-specific packages declared by an mpack.
 */
public class MpackOsSpecific {
  @SerializedName("osFamily")
  private String osFamily;

  @SerializedName("packages")
  private List<String> packages;

  public String getOsFamily() {
    return osFamily;
  }

  public void setOsFamily(String osFamily) {
    this.osFamily = osFamily;
  }

  public List<String> getPackages() {
    return packages == null ? Collections.emptyList() : Collections.unmodifiableList(packages);
  }

  public void setPackages(List<String> packages) {
    this.packages = packages;
  }

  @Override
  public boolean equals(Object object) {
    if (this == object) {
      return true;
    }
    if (!(object instanceof MpackOsSpecific)) {
      return false;
    }
    MpackOsSpecific that = (MpackOsSpecific) object;
    return Objects.equals(osFamily, that.osFamily) && Objects.equals(packages, that.packages);
  }

  @Override
  public int hashCode() {
    return Objects.hash(osFamily, packages);
  }
}
