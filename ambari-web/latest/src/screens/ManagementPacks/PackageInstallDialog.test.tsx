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

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PackageInstallDialog from "./PackageInstallDialog";
import type { RegisteredMpack } from "./model";

const lifecycle = vi.hoisted(() => ({definitions: vi.fn(), hosts: vi.fn(), install: vi.fn()}));
vi.mock("./packageLifecycle", () => ({PackageLifecycle: lifecycle}));
const pack: RegisteredMpack = {id: 1, mpackId: "http", name: "http", displayName: "HTTP", description: "",
  version: "1", repositoryVersionId: 7, stackName: "MPACK_fixture", modules: []};
const field = {type: "string", description: "", secretReference: false, emptyValid: true, entries: []};

describe("package installation schema projection", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    lifecycle.hosts.mockResolvedValue(["host.example"]);
    lifecycle.install.mockResolvedValue({});
    lifecycle.definitions.mockResolvedValue([{name: "HTTP_ECHO",
      components: [{name: "HTTP_ECHO_SERVER", category: "SLAVE", cardinality: "1"}],
      defaults: {http: {port: "18080", enabled: "true", mode: "safe", credential: "secret://mpack.HTTP_ECHO.auth"}},
      fields: {http: {
        port: {...field, type: "int", minimum: 1, maximum: 65535, emptyValid: false},
        enabled: {...field, type: "boolean"},
        mode: {...field, entries: [{value: "safe", label: "Safe"}, {value: "fast", label: "Fast"}]},
        credential: {...field, secretReference: true},
      }},
    }]);
  });

  it("renders typed fields through existing configuration metadata and submits scoped references", async () => {
    const submitted = vi.fn();
    render(<PackageInstallDialog pack={pack} cluster="cluster" close={vi.fn()} submitted={submitted} />);
    const port = await screen.findByRole("spinbutton", {name: "port"});
    expect(port.getAttribute("min")).toBe("1");
    expect(port.getAttribute("max")).toBe("65535");
    expect(screen.getByRole("combobox", {name: "mode"}).textContent).toContain("Safe");
    fireEvent.click(screen.getByRole("checkbox", {name: "host.example"}));
    fireEvent.change(screen.getByRole("combobox", {name: "enabled"}), {target: {value: "false"}});
    fireEvent.submit(port.closest("form")!);
    await waitFor(() => expect(submitted).toHaveBeenCalledWith("HTTP_ECHO"));
    expect(lifecycle.install).toHaveBeenCalledWith("cluster", 7, expect.anything(),
      {HTTP_ECHO_SERVER: ["host.example"]}, {http: expect.objectContaining({enabled: "false", credential: "secret://mpack.HTTP_ECHO.auth"})});
  });

  it("rejects literal or foreign-service credentials before any install mutation", async () => {
    render(<PackageInstallDialog pack={pack} cluster="cluster" close={vi.fn()} submitted={vi.fn()} />);
    const credential = await screen.findByRole("textbox", {name: "credential (credential reference)"});
    fireEvent.click(screen.getByRole("checkbox", {name: "host.example"}));
    for (const value of ["synthetic-literal", "secret://mpack.OTHER.auth"]) {
      fireEvent.change(credential, {target: {value}});
      fireEvent.submit(credential.closest("form")!);
      expect(await screen.findByRole("alert")).toHaveTextContent("Use a scoped credential reference");
      expect(lifecycle.install).not.toHaveBeenCalled();
    }
  });
});
