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

import { useEffect, useId, useState } from "react";
import { Alert, Button, Form, Modal, Spinner } from "react-bootstrap";
import { RegisteredMpack } from "./model";
import { PackageLifecycle, PackageService } from "./packageLifecycle";

export default function PackageInstallDialog({ pack, cluster, close, submitted }: {
  pack: RegisteredMpack; cluster: string; close: () => void; submitted: (service: string) => void;
}) {
  const formId = useId();
  const [definitions, setDefinitions] = useState<PackageService[]>([]);
  const [service, setService] = useState<PackageService>();
  const [hosts, setHosts] = useState<string[]>([]);
  const [assignments, setAssignments] = useState<Record<string, string[]>>({});
  const [configs, setConfigs] = useState<PackageService["defaults"]>({});
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    let current = true;
    Promise.all([PackageLifecycle.definitions(pack.stackName!, pack.version), PackageLifecycle.hosts(cluster)])
      .then(([services, available]) => {
        if (!current) return;
        setDefinitions(services); setHosts(available);
        setService(services[0]); setConfigs(services[0]?.defaults || {});
      }).catch(() => { if (current) setError("Package definitions or cluster hosts could not be loaded. Close and reopen to retry."); })
      .finally(() => { if (current) setBusy(false); });
    return () => { current = false; };
  }, [pack.stackName, pack.version, cluster]);

  async function install() {
    if (!service || !pack.repositoryVersionId) return;
    for (const [type, fields] of Object.entries(service.fields || {})) {
      for (const [name, field] of Object.entries(fields)) {
        if (field.secretReference) {
          const value = configs[type]?.[name] || "";
          const prefix = `secret://mpack.${service.name}.`;
          if (!value.startsWith(prefix) || !/^[A-Za-z0-9_.-]{1,128}$/.test(value.slice(prefix.length))) {
            setError(`Use a scoped credential reference for ${type}/${name}; enter no credential value.`); return;
          }
        }
      }
    }
    for (const component of service.components) {
      const count = (assignments[component.name] || []).length;
      const bounds = /^(\d+)(?:(\+)|-(\d+))?$/.exec(component.cardinality);
      if (!bounds || count < Number(bounds[1]) || (!bounds[2] && count > Number(bounds[3] || bounds[1]))) {
        setError(`Select ${component.cardinality} host(s) for ${component.name}.`); return;
      }
    }
    setBusy(true); setError("");
    try {
      await PackageLifecycle.install(cluster, pack.repositoryVersionId, service, assignments, configs);
      submitted(service.name);
    } catch {
      setError("Installation could not be submitted completely. Existing records are retained. Refresh service status before retrying; server authorization, package conflicts and task failures are authoritative.");
    } finally { setBusy(false); }
  }
  return <Modal show onHide={() => !busy && close()} size="lg" backdrop="static">
    <Modal.Header closeButton={!busy}><Modal.Title>Install {pack.displayName} {pack.version}</Modal.Title></Modal.Header>
    <Modal.Body>
      <Form id={formId} onSubmit={(event) => { event.preventDefault(); void install(); }}>
      <p>Cluster: <strong>{cluster}</strong>. Installation creates or resumes an existing Ambari service. Start it after installation succeeds.</p>
      {error && <Alert variant="danger">{error}</Alert>}
      <Form.Group className="mb-3"><Form.Label>Service</Form.Label>
        <Form.Select value={service?.name || ""} disabled={busy} onChange={(event) => {
          const selected = definitions.find((item) => item.name === event.target.value);
          setService(selected); setConfigs(selected?.defaults || {}); setAssignments({});
        }}>{definitions.map((item) => <option key={item.name}>{item.name}</option>)}</Form.Select>
      </Form.Group>
      {service?.components.map((component) => <fieldset key={component.name} className="mb-3">
        <legend className="h6">{component.name} — {component.cardinality} host(s)</legend>
        {hosts.map((host) => <Form.Check key={host} type="checkbox" label={host} disabled={busy}
          checked={(assignments[component.name] || []).includes(host)} onChange={(event) => {
            const checked = event.target.checked;
            setAssignments((current) => ({ ...current, [component.name]: checked
              ? [...(current[component.name] || []), host] : (current[component.name] || []).filter((item) => item !== host) }));
          }} />)}
      </fieldset>)}
      {Object.entries(configs).map(([type, properties]) => <fieldset key={type} className="mb-3">
        <legend className="h6">{type}</legend>
        {Object.entries(properties).map(([name, value]) => {
          const field = service?.fields?.[type]?.[name];
          const options = field?.entries.length ? field.entries : field?.type === "boolean"
            ? [{value: "true", label: "true"}, {value: "false", label: "false"}] : [];
          const change = (next: string) => {
            setConfigs((current) => ({ ...current, [type]: { ...current[type], [name]: next } }));
          };
          return <Form.Group key={name} className="mb-2" controlId={`${formId}-${type}-${name}`}>
          <Form.Label>{name}{field?.secretReference && " (credential reference)"}</Form.Label>
          {options.length ? <Form.Select value={value} disabled={busy} required={field?.emptyValid === false}
            onChange={(event) => change(event.target.value)}>
            {!options.some((option) => option.value === value) && <option value="">Select a value</option>}
            {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </Form.Select> : <Form.Control value={value} disabled={busy} autoComplete="off"
            type={field?.type === "int" || field?.type === "float" ? "number" : "text"}
            min={field?.minimum} max={field?.maximum} step={field?.type === "float" ? "any" : 1}
            required={field?.secretReference || field?.emptyValid === false} onChange={(event) => {
            const next = event.target.value;
            change(next);
          }} />}
          {field?.description && <Form.Text>{field.description}</Form.Text>}
        </Form.Group>; })}
      </fieldset>)}
      {!hosts.length && !busy && <Alert variant="warning">This cluster has no registered hosts.</Alert>}
      </Form>
    </Modal.Body>
    <Modal.Footer><Button variant="secondary" onClick={close} disabled={busy}>Cancel</Button>
      <Button type="submit" form={formId} disabled={busy || !service || !hosts.length}>
        {busy && <Spinner size="sm" className="me-2" />}Install / resume
      </Button>
    </Modal.Footer>
  </Modal>;
}
