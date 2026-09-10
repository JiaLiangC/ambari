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
package org.apache.ambari.server.api.services;

import java.util.Collections;

import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.apache.ambari.server.api.resources.ResourceInstance;
import org.apache.ambari.server.controller.MpackResponse.MpackResponseWrapper;
import org.apache.ambari.server.controller.internal.MpackResourceProvider;
import org.apache.ambari.server.controller.spi.Resource;
import org.apache.http.HttpStatus;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiImplicitParam;
import io.swagger.annotations.ApiImplicitParams;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;


/**
 * Service for Mpacks Management.
 * Endpoint for Mpack Data
 */
@Path("/mpacks/")
@Api(value = "Mpacks", description = "Endpoint for mpack-specific operations")
public class MpacksService extends BaseService {

  private static final String MPACK_REQUEST_TYPE = "org.apache.ambari.server.api.services.MpackRequestSwagger";

  public MpacksService() {
    super();
  }

  /**
   * Handles: GET /mpacks/
   *
   * @param headers http headers
   * @param ui      uri info
   * @return All the existing mpack definitions
   *
   */
  @GET
  @Produces(MediaType.TEXT_PLAIN)
  @ApiOperation(value = "Returns all mpacks registered with this Ambari instance",
    response = MpackResponseWrapper.class, responseContainer = RESPONSE_CONTAINER_LIST)
  @ApiImplicitParams({
    @ApiImplicitParam(name = QUERY_FIELDS, value = QUERY_FILTER_DESCRIPTION, dataType = DATA_TYPE_STRING,
      paramType = PARAM_TYPE_QUERY, defaultValue = MpackResourceProvider.MPACK_RESOURCE_ID),
    @ApiImplicitParam(name = QUERY_SORT, value = QUERY_SORT_DESCRIPTION, dataType = DATA_TYPE_STRING,
      paramType = PARAM_TYPE_QUERY),
    @ApiImplicitParam(name = QUERY_PAGE_SIZE, value = QUERY_PAGE_SIZE_DESCRIPTION, defaultValue = DEFAULT_PAGE_SIZE,
      dataType = DATA_TYPE_INT, paramType = PARAM_TYPE_QUERY),
    @ApiImplicitParam(name = QUERY_FROM, value = QUERY_FROM_DESCRIPTION, allowableValues = QUERY_FROM_VALUES,
      defaultValue = DEFAULT_FROM, dataType = DATA_TYPE_INT, paramType = PARAM_TYPE_QUERY),
    @ApiImplicitParam(name = QUERY_TO, value = QUERY_TO_DESCRIPTION, allowableValues = QUERY_TO_VALUES,
      dataType = DATA_TYPE_INT, paramType = PARAM_TYPE_QUERY),
  })
  @ApiResponses({
    @ApiResponse(code = HttpStatus.SC_OK, message = MSG_SUCCESSFUL_OPERATION),
    @ApiResponse(code = HttpStatus.SC_NOT_FOUND, message = MSG_RESOURCE_NOT_FOUND),
    @ApiResponse(code = HttpStatus.SC_UNAUTHORIZED, message = MSG_NOT_AUTHENTICATED),
    @ApiResponse(code = HttpStatus.SC_FORBIDDEN, message = MSG_PERMISSION_DENIED),
    @ApiResponse(code = HttpStatus.SC_INTERNAL_SERVER_ERROR, message = MSG_SERVER_ERROR),
  })
  public Response getMpacks(@Context HttpHeaders headers, @Context UriInfo ui) {
    return handleRequest(headers, null, ui, Request.Type.GET, createMpackResource(null));
  }

  /**
   * Handles: POST /mpacks/
   *
   * @param headers http headers
   * @param ui      uri info
   * @param body    request body
   * @return information regarding the created mpack
   */
  @POST
  @Produces(MediaType.TEXT_PLAIN)
  @ApiOperation(value = "Registers an mpack with this Ambari mpack")
  @ApiImplicitParams({
    @ApiImplicitParam(dataType = MPACK_REQUEST_TYPE, paramType = PARAM_TYPE_BODY)
  })
  @ApiResponses({
    @ApiResponse(code = HttpStatus.SC_CREATED, message = MSG_SUCCESSFUL_OPERATION),
    @ApiResponse(code = HttpStatus.SC_ACCEPTED, message = MSG_REQUEST_ACCEPTED),
    @ApiResponse(code = HttpStatus.SC_BAD_REQUEST, message = MSG_INVALID_ARGUMENTS),
    @ApiResponse(code = HttpStatus.SC_CONFLICT, message = MSG_RESOURCE_ALREADY_EXISTS),
    @ApiResponse(code = HttpStatus.SC_UNAUTHORIZED, message = MSG_NOT_AUTHENTICATED),
    @ApiResponse(code = HttpStatus.SC_FORBIDDEN, message = MSG_PERMISSION_DENIED),
    @ApiResponse(code = HttpStatus.SC_INTERNAL_SERVER_ERROR, message = MSG_SERVER_ERROR),
  })
  public Response createMpacks(String body, @Context HttpHeaders headers, @Context UriInfo ui) {
    return handleRequest(headers, body, ui, Request.Type.POST, createMpackResource(null));
  }

  /** Upload one deployable release; registration still uses the standard resource provider. */
  @POST
  @Path("imports")
  @jakarta.ws.rs.Consumes(MediaType.APPLICATION_OCTET_STREAM)
  @Produces(MediaType.APPLICATION_JSON)
  public Response uploadMpack(java.io.InputStream input, @Context HttpHeaders headers, @Context UriInfo ui) {
    if (!org.apache.ambari.server.security.authorization.AuthorizationHelper.isAuthorized(
        org.apache.ambari.server.security.authorization.ResourceType.AMBARI, null,
        org.apache.ambari.server.security.authorization.RoleAuthorization.AMBARI_MANAGE_STACK_VERSIONS)) {
      return Response.status(Response.Status.FORBIDDEN).entity("{\"message\":\"Package import is not authorized\"}").build();
    }
    java.nio.file.Path upload = null;
    try {
      upload = java.nio.file.Files.createTempFile("mpack-upload-", ".mpack");
      long maximum = 513L * 1024 * 1024 + 65536;
      long total = 0;
      long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MINUTES.toNanos(5);
      try (java.io.OutputStream output = java.nio.file.Files.newOutputStream(upload)) {
        byte[] buffer = new byte[65536];
        int count;
        while ((count = input.read(buffer)) != -1) {
          total += count;
          if (total > maximum || System.nanoTime() > deadline) {
            return Response.status(413).entity("{\"message\":\"Upload exceeds size or duration limit\"}").build();
          }
          output.write(buffer, 0, count);
        }
      }
      if (total == 0) {
        return Response.status(Response.Status.BAD_REQUEST).entity("{\"message\":\"Package upload is empty\"}").build();
      }
      String body = new com.google.gson.Gson().toJson(java.util.Map.of("MpackInfo",
          java.util.Map.of("mpack_uri", upload.toUri().toString())));
      return handleRequest(headers, body, ui, Request.Type.POST, createMpackResource(null));
    } catch (java.io.IOException failure) {
      return Response.status(Response.Status.BAD_REQUEST).entity("{\"message\":\"Package upload could not be completed\"}").build();
    } finally {
      if (upload != null) {
        try {
          java.nio.file.Files.deleteIfExists(upload);
        } catch (java.io.IOException ignored) {
          // A failed import is never made available; the temporary file has no execution authority.
        }
      }
    }
  }

  /***
   * Handles: GET /mpacks/{id}
   * Return a specific mpack given an id
   *
   * @param
   */
  @GET
  @Path("{id}")
  @Produces(MediaType.TEXT_PLAIN)
  @ApiOperation(value = "Returns information about a specific mpack that is registered with this Ambari instance",
    response = MpackResponseWrapper.class)
  @ApiImplicitParams({
    @ApiImplicitParam(name = QUERY_FIELDS, value = QUERY_FILTER_DESCRIPTION, dataType = DATA_TYPE_STRING,
      paramType = PARAM_TYPE_QUERY, defaultValue = MpackResourceProvider.ALL_PROPERTIES),
  })
  @ApiResponses({
    @ApiResponse(code = HttpStatus.SC_OK, message = MSG_SUCCESSFUL_OPERATION),
    @ApiResponse(code = HttpStatus.SC_NOT_FOUND, message = MSG_RESOURCE_NOT_FOUND),
    @ApiResponse(code = HttpStatus.SC_UNAUTHORIZED, message = MSG_NOT_AUTHENTICATED),
    @ApiResponse(code = HttpStatus.SC_FORBIDDEN, message = MSG_PERMISSION_DENIED),
    @ApiResponse(code = HttpStatus.SC_INTERNAL_SERVER_ERROR, message = MSG_SERVER_ERROR),
  })
  public Response getMpack(@Context HttpHeaders headers, @Context UriInfo ui, @PathParam("id") String id) {

    return handleRequest(headers, null, ui, Request.Type.GET, createMpackResource(id));
  }

  /**
   * Handles requests for immutable repository metadata shipped by an mpack.
   * Mutable repository settings remain owned by the repository-version API.
   */
  @Path("{id}/operating_systems")
  public MpackOperatingSystemService getOperatingSystemsHandler(@PathParam("id") String id) {
    return new MpackOperatingSystemService(id);
  }

  @DELETE
  @Path("{id}")
  @Produces(MediaType.TEXT_PLAIN)
  @ApiOperation(value = "Deletes a selected management pack")
  @ApiImplicitParams({
    @ApiImplicitParam(name = QUERY_FIELDS, value = QUERY_FILTER_DESCRIPTION, dataType = DATA_TYPE_STRING,
                  paramType = PARAM_TYPE_QUERY, defaultValue = MpackResourceProvider.ALL_PROPERTIES),
  })
  @ApiResponses({
          @ApiResponse(code = HttpStatus.SC_OK, message = MSG_SUCCESSFUL_OPERATION),
          @ApiResponse(code = HttpStatus.SC_NOT_FOUND, message = MSG_CLUSTER_OR_HOST_NOT_FOUND),
          @ApiResponse(code = HttpStatus.SC_UNAUTHORIZED, message = MSG_NOT_AUTHENTICATED),
          @ApiResponse(code = HttpStatus.SC_FORBIDDEN, message = MSG_PERMISSION_DENIED),
          @ApiResponse(code = HttpStatus.SC_INTERNAL_SERVER_ERROR, message = MSG_SERVER_ERROR),
  })
  public Response deleteMpack(String body, @Context HttpHeaders headers, @Context UriInfo ui, @PathParam("id") String id) {
    return handleRequest(headers, body, ui, Request.Type.DELETE,
            createMpackResource(id));
  }

  /**
   * Create an mpack resource instance
   * @param id
   * @return ResourceInstance
   */
  private ResourceInstance createMpackResource(String id) {
    return createResource(Resource.Type.Mpack,
            Collections.singletonMap(Resource.Type.Mpack, id));

  }

}
