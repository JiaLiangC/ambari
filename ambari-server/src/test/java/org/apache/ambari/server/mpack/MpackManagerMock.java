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

import java.io.File;

import org.apache.ambari.server.orm.dao.MpackDAO;
import org.apache.ambari.server.orm.dao.StackDAO;

import com.google.inject.Inject;
import com.google.inject.assistedinject.Assisted;

/**
 * Test binding for the assisted manager factory. Production behavior remains
 * in {@link MpackManager}; this type exists only for Guice's test module.
 */
public class MpackManagerMock extends MpackManager {

  @Inject
  public MpackManagerMock(
      @Assisted("mpacksv2Staging") File mpacksStagingLocation,
      @Assisted("stackRoot") File stackRootDir,
      MpackDAO mpackDAO,
      StackDAO stackDAO) {
    super(mpacksStagingLocation, stackRootDir, mpackDAO, stackDAO);
  }
}
