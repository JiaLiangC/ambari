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
package org.apache.ambari.server.api.services;

import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.apache.ambari.annotations.ApiIgnore;
import org.apache.ambari.server.api.resources.ResourceInstance;
import org.apache.ambari.server.controller.spi.Resource;

/**
 * Read-only service for repository metadata shipped by a registered mpack.
 */
public class MpackOperatingSystemService extends BaseService {
  private final String mpackId;

  public MpackOperatingSystemService(String mpackId) {
    this.mpackId = mpackId;
  }

  @GET
  @ApiIgnore
  @Produces(MediaType.TEXT_PLAIN)
  public Response getOperatingSystems(@Context HttpHeaders headers, @Context UriInfo uriInfo) {
    return handleRequest(headers, null, uriInfo, Request.Type.GET, createResource(null));
  }

  @GET
  @ApiIgnore
  @Path("{osType}")
  @Produces(MediaType.TEXT_PLAIN)
  public Response getOperatingSystem(@Context HttpHeaders headers, @Context UriInfo uriInfo,
      @PathParam("osType") String osType) {
    return handleRequest(headers, null, uriInfo, Request.Type.GET, createResource(osType));
  }

  private ResourceInstance createResource(String osType) {
    Map<Resource.Type, String> keys = new HashMap<>();
    keys.put(Resource.Type.Mpack, mpackId);
    keys.put(Resource.Type.MpackOperatingSystem, osType);
    return createResource(Resource.Type.MpackOperatingSystem, keys);
  }
}
