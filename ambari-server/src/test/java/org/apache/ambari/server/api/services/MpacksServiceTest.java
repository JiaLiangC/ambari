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
package org.apache.ambari.server.api.services;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;

import org.apache.ambari.server.api.resources.ResourceInstance;
import org.apache.ambari.server.api.services.parsers.RequestBodyParser;
import org.apache.ambari.server.api.services.serializers.ResultSerializer;
import org.apache.ambari.server.controller.spi.Resource;

/**
 * Unit tests for MpacksService
 */
public class MpacksServiceTest extends BaseServiceTest{
  @org.junit.Test
  public void testUploadDenialDoesNotReadRequestBody() {
    org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
        org.apache.ambari.server.security.TestAuthenticationFactory.createServiceAdministrator());
    try {
      java.io.InputStream input = new java.io.InputStream() {
        @Override
        public int read() {
          throw new AssertionError("Unauthorized upload body must not be read");
        }
      };
      org.junit.Assert.assertEquals(403, new MpacksService().uploadMpack(input, null, null).getStatus());
    } finally {
      org.springframework.security.core.context.SecurityContextHolder.clearContext();
    }
  }

  @org.junit.Test
  public void testUploadStagesExactBytesAndDeletesTemporaryFileAfterRegistration() throws Exception {
    org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
        org.apache.ambari.server.security.TestAuthenticationFactory.createAdministrator());
    java.nio.file.Path[] staged = new java.nio.file.Path[1];
    byte[] content = "transport body fixture".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    MpacksService service = new MpacksService() {
      @Override
      protected ResourceInstance createResource(Resource.Type type, Map<Resource.Type, String> ids) {
        return null;
      }

      @Override
      protected jakarta.ws.rs.core.Response handleRequest(HttpHeaders headers, String body, UriInfo uri,
          Request.Type method, ResourceInstance resource) {
        org.junit.Assert.assertEquals(Request.Type.POST, method);
        String source = com.google.gson.JsonParser.parseString(body).getAsJsonObject()
            .getAsJsonObject("MpackInfo").get("mpack_uri").getAsString();
        staged[0] = java.nio.file.Path.of(java.net.URI.create(source));
        try {
          org.junit.Assert.assertArrayEquals(content, java.nio.file.Files.readAllBytes(staged[0]));
          org.junit.Assert.assertTrue(staged[0].toString().endsWith(".mpack"));
        } catch (java.io.IOException failure) {
          throw new AssertionError(failure);
        }
        return jakarta.ws.rs.core.Response.status(201).build();
      }
    };
    try {
      org.junit.Assert.assertEquals(201, service.uploadMpack(new java.io.ByteArrayInputStream(content), null, null).getStatus());
      org.junit.Assert.assertNotNull(staged[0]);
      org.junit.Assert.assertFalse(java.nio.file.Files.exists(staged[0]));
    } finally {
      org.springframework.security.core.context.SecurityContextHolder.clearContext();
      if (staged[0] != null) { java.nio.file.Files.deleteIfExists(staged[0]); }
    }
  }

  @org.junit.Test
  public void testEmptyAndInterruptedUploadsNeverReachRegistrationOrEchoInput() {
    org.springframework.security.core.context.SecurityContextHolder.getContext().setAuthentication(
        org.apache.ambari.server.security.TestAuthenticationFactory.createAdministrator());
    MpacksService service = new MpacksService() {
      @Override
      protected jakarta.ws.rs.core.Response handleRequest(HttpHeaders headers, String body, UriInfo uri,
          Request.Type method, ResourceInstance resource) {
        throw new AssertionError("Incomplete upload must not reach registration");
      }
    };
    try {
      org.junit.Assert.assertEquals(400, service.uploadMpack(new java.io.ByteArrayInputStream(new byte[0]), null, null).getStatus());
      java.io.InputStream interrupted = new java.io.InputStream() {
        @Override
        public int read() throws java.io.IOException {
          throw new java.io.IOException("synthetic input marker must not reach response");
        }
      };
      jakarta.ws.rs.core.Response response = service.uploadMpack(interrupted, null, null);
      org.junit.Assert.assertEquals(400, response.getStatus());
      org.junit.Assert.assertFalse(response.getEntity().toString().contains("synthetic input marker"));
    } finally {
      org.springframework.security.core.context.SecurityContextHolder.clearContext();
    }
  }

  @Override
  public List<BaseServiceTest.ServiceTestInvocation> getTestInvocations() throws Exception {
    List<BaseServiceTest.ServiceTestInvocation> listInvocations = new ArrayList<>();

    // getMpacks
    MpacksService service = new TestMpacksService("null");
    Method m = service.getClass().getMethod("getMpacks", HttpHeaders.class, UriInfo.class);
    Object[] args = new Object[]{getHttpHeaders(), getUriInfo()};
    listInvocations.add(new ServiceTestInvocation(Request.Type.GET, service, m, args, null));

    // getMpack
    service = new TestMpacksService("1");
    m = service.getClass().getMethod("getMpack", HttpHeaders.class, UriInfo.class, String.class);
    args = new Object[]{getHttpHeaders(), getUriInfo(), ""};
    listInvocations.add(new ServiceTestInvocation(Request.Type.GET, service, m, args, null));

    //createMpacks
    service = new TestMpacksService(null);
    m = service.getClass().getMethod("createMpacks", String.class, HttpHeaders.class, UriInfo.class);
    args = new Object[]{"body", getHttpHeaders(), getUriInfo()};
    listInvocations.add(new ServiceTestInvocation(Request.Type.POST, service, m, args, "body"));

    return listInvocations;
  }
  private class TestMpacksService extends MpacksService {

    private String m_mpackId;

    private TestMpacksService(String mpackId) {
      super();
      m_mpackId = mpackId;
    }

    @Override
    protected ResourceInstance createResource(Resource.Type type, Map<Resource.Type, String> mapIds) {
      return getTestResource();
    }

    @Override
    RequestFactory getRequestFactory() {
      return getTestRequestFactory();
    }

    @Override
    protected RequestBodyParser getBodyParser() {
      return getTestBodyParser();
    }

    @Override
    protected ResultSerializer getResultSerializer() {
      return getTestResultSerializer();
    }
  }


}
