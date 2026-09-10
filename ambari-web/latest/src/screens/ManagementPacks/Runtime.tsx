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

import { useCallback, useEffect, useMemo, useState } from "react";
import { Alert, Badge, Button, Card, Col, Form, Row, Spinner, Table } from "react-bootstrap";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faArrowLeft,
  faBan,
  faCheck,
  faRotate,
  faWandMagicSparkles,
} from "@fortawesome/free-solid-svg-icons";
import { useNavigate, useParams } from "react-router-dom";
import toast from "react-hot-toast";
import { useAuth } from "../../hooks/useAuth";
import MpackRuntimeApi from "../../api/mpackRuntimeApi";
import {
  normalizeCapabilities,
  normalizeObservations,
  normalizeOperations,
  normalizePlan,
  operationStateVariant,
  RuntimeCapability,
  RuntimeObservation,
  RuntimeOperation,
  RuntimePlan,
} from "./runtimeModel";

function errorMessage(error: unknown, fallback: string): string {
  if (error && typeof error === "object") {
    const candidate = error as {
      message?: string;
      response?: { data?: { message?: string } };
    };
    return candidate.response?.data?.message || candidate.message || fallback;
  }
  return fallback;
}

function timestamp(value?: string) {
  if (!value) return "Unknown";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function ObservationTable({ observations }: { observations: RuntimeObservation[] }) {
  if (!observations.length) {
    return <p className="text-muted mb-0">No observations are available for this management pack.</p>;
  }
  return (
    <Table responsive hover size="sm" className="align-middle mb-0">
      <thead>
        <tr><th>Kind</th><th>Name</th><th>State</th><th>Value</th><th>Observed</th><th>Details</th></tr>
      </thead>
      <tbody>
        {observations.map((observation, index) => (
          <tr key={`${observation.kind}-${observation.name}-${index}`}>
            <td>{observation.kind}</td>
            <td>{observation.name}</td>
            <td><Badge bg={observation.stale ? "warning" : observation.state === "HEALTHY" ? "success" : "secondary"}>{observation.stale ? "UNKNOWN" : observation.state}</Badge></td>
            <td>{observation.value || "-"}</td>
            <td>{timestamp(observation.observedAt)}</td>
            <td>{observation.message || "-"}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

function CapabilityTable({ capabilities }: { capabilities: RuntimeCapability[] }) {
  if (!capabilities.length) {
    return <p className="text-muted mb-0">Capability discovery returned no entries.</p>;
  }
  return (
    <Table responsive hover size="sm" className="align-middle mb-0">
      <thead><tr><th>Capability</th><th>Adapter</th><th>Availability</th><th>Reason</th></tr></thead>
      <tbody>
        {capabilities.map((capability) => (
          <tr key={capability.name}>
            <td className="font-monospace">{capability.name}</td>
            <td>{capability.adapter || "-"}</td>
            <td><Badge bg={capability.supported ? "success" : "secondary"}>{capability.supported ? "Supported" : "Unsupported"}</Badge></td>
            <td>{capability.reason || "-"}</td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export default function MpackRuntime() {
  const navigate = useNavigate();
  const { mpackId } = useParams();
  const { hasAuthorization } = useAuth();
  const parsedMpackId = Number(mpackId);
  const canManage = hasAuthorization("AMBARI.MANAGE_STACK_VERSIONS");
  const [capabilities, setCapabilities] = useState<RuntimeCapability[]>([]);
  const [observations, setObservations] = useState<RuntimeObservation[]>([]);
  const [operations, setOperations] = useState<RuntimeOperation[]>([]);
  const [schema, setSchema] = useState<unknown>();
  const [plan, setPlan] = useState<RuntimePlan>();
  const [selectedCapability, setSelectedCapability] = useState("");
  const [desired, setDesired] = useState("{}");
  const [busy, setBusy] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    if (!Number.isSafeInteger(parsedMpackId) || parsedMpackId <= 0) {
      setError("The management pack identifier is invalid.");
      setLoading(false);
      return;
    }
    setLoading(true);
    setError("");
    const results = await Promise.allSettled([
      MpackRuntimeApi.getSchema(parsedMpackId),
      MpackRuntimeApi.getCapabilities(parsedMpackId),
      MpackRuntimeApi.getObservations(parsedMpackId),
      MpackRuntimeApi.getOperations(parsedMpackId),
    ]);
    const failures: string[] = [];
    const [schemaResult, capabilityResult, observationResult, operationResult] = results;
    if (schemaResult.status === "fulfilled") setSchema(schemaResult.value);
    else failures.push(errorMessage(schemaResult.reason, "Schema unavailable"));
    if (capabilityResult.status === "fulfilled") {
      const nextCapabilities = normalizeCapabilities(capabilityResult.value);
      setCapabilities(nextCapabilities);
      setSelectedCapability((current) => current || nextCapabilities.find((item) => item.supported)?.name || "");
    } else failures.push(errorMessage(capabilityResult.reason, "Capabilities unavailable"));
    if (observationResult.status === "fulfilled") setObservations(normalizeObservations(observationResult.value));
    else failures.push(errorMessage(observationResult.reason, "Observations unavailable"));
    if (operationResult.status === "fulfilled") setOperations(normalizeOperations(operationResult.value));
    else failures.push(errorMessage(operationResult.reason, "Operations unavailable"));
    if (failures.length) setError(`Some runtime data could not be loaded: ${failures.join("; ")}`);
    setLoading(false);
  }, [parsedMpackId]);

  useEffect(() => { void load(); }, [load]);

  const availableCapabilities = useMemo(
    () => capabilities.filter((capability) => capability.supported),
    [capabilities],
  );

  async function createPlan() {
    if (!selectedCapability || !Number.isSafeInteger(parsedMpackId)) return;
    let desiredValue: Record<string, unknown>;
    try {
      const parsed = JSON.parse(desired) as unknown;
      if (parsed === null || Array.isArray(parsed) || typeof parsed !== "object") throw new Error("Desired input must be a JSON object.");
      desiredValue = parsed as Record<string, unknown>;
    } catch (parseError) {
      setError(errorMessage(parseError, "Desired input is not valid JSON."));
      return;
    }
    setBusy("plan");
    setError("");
    try {
      const response = await MpackRuntimeApi.plan(parsedMpackId, {
        capability: selectedCapability,
        desired: desiredValue,
      });
      setPlan(normalizePlan(response));
      toast.success("Operation plan prepared.");
    } catch (requestError) {
      setError(errorMessage(requestError, "The operation plan could not be prepared."));
    } finally {
      setBusy("");
    }
  }

  async function applyPlan() {
    if (!plan || !selectedCapability || !Number.isSafeInteger(parsedMpackId)) return;
    setBusy("apply");
    setError("");
    try {
      await MpackRuntimeApi.createOperation(parsedMpackId, {
        capability: selectedCapability,
        plan,
      });
      toast.success("Operation submitted.");
      setPlan(undefined);
      await load();
    } catch (requestError) {
      setError(errorMessage(requestError, "The operation could not be submitted."));
    } finally {
      setBusy("");
    }
  }

  async function mutateOperation(operation: RuntimeOperation, action: "cancel" | "recover") {
    if (!Number.isSafeInteger(parsedMpackId)) return;
    setBusy(`${action}-${operation.id}`);
    setError("");
    try {
      if (action === "cancel") await MpackRuntimeApi.cancelOperation(parsedMpackId, operation.id);
      else await MpackRuntimeApi.recoverOperation(parsedMpackId, operation.id, operation.recoveryActions[0] || "retry");
      toast.success(action === "cancel" ? "Operation cancellation requested." : "Operation recovery requested.");
      await load();
    } catch (requestError) {
      setError(errorMessage(requestError, `The operation could not be ${action}ed.`));
    } finally {
      setBusy("");
    }
  }

  if (loading && !capabilities.length && !observations.length && !operations.length) return <Spinner animation="border" className="m-4" />;

  return (
    <main className="container-fluid px-4 py-4">
      <div className="d-flex flex-wrap align-items-center justify-content-between gap-3 mb-4">
        <div className="d-flex align-items-center gap-3">
          <Button aria-label="Back to management packs" variant="outline-secondary" size="sm" onClick={() => navigate("/main/admin/mpacks")}>
            <FontAwesomeIcon icon={faArrowLeft} />
          </Button>
          <div><h2 className="mb-0">Runtime</h2><span className="text-muted">Management pack {mpackId}</span></div>
        </div>
        <Button variant="outline-secondary" onClick={() => void load()} disabled={Boolean(busy)}>
          <FontAwesomeIcon icon={faRotate} className="me-2" />Refresh
        </Button>
      </div>
      {error && <Alert variant="warning" dismissible onClose={() => setError("")}>{error}</Alert>}

      <Row className="g-4 mb-4">
        <Col xl={6}>
          <Card><Card.Header>Capabilities</Card.Header><Card.Body><CapabilityTable capabilities={capabilities} /></Card.Body></Card>
        </Col>
        <Col xl={6}>
          <Card><Card.Header>Schema</Card.Header><Card.Body>
            {schema === undefined ? <p className="text-muted mb-0">Schema is unavailable.</p> : <pre className="small mb-0" style={{ maxHeight: 280, overflow: "auto" }}>{JSON.stringify(schema, null, 2)}</pre>}
          </Card.Body></Card>
        </Col>
      </Row>

      <Card className="mb-4"><Card.Header>Plan and apply operation</Card.Header><Card.Body>
        {!canManage && <Alert variant="info">You can inspect runtime metadata, but an Ambari management permission is required to plan or apply operations.</Alert>}
        <Row className="g-3 align-items-end">
          <Col md={4}><Form.Label>Capability</Form.Label><Form.Select value={selectedCapability} onChange={(event) => setSelectedCapability(event.target.value)} disabled={!canManage || Boolean(busy)}><option value="">Select capability</option>{availableCapabilities.map((capability) => <option key={capability.name} value={capability.name}>{capability.name}</option>)}</Form.Select></Col>
          <Col md={5}><Form.Label>Desired JSON</Form.Label><Form.Control as="textarea" rows={2} value={desired} onChange={(event) => setDesired(event.target.value)} disabled={!canManage || Boolean(busy)} /></Col>
          <Col md={3}><Button className="w-100" variant="outline-primary" onClick={() => void createPlan()} disabled={!canManage || !selectedCapability || Boolean(busy)}>{busy === "plan" ? <Spinner size="sm" className="me-2" /> : <FontAwesomeIcon icon={faWandMagicSparkles} className="me-2" />}Prepare plan</Button></Col>
        </Row>
        {plan && <div className="mt-3"><h3 className="h6">Plan {plan.id || "draft"}</h3>{plan.diagnostics.length > 0 && <Alert variant="warning"><ul className="mb-0">{plan.diagnostics.map((diagnostic, index) => <li key={`${diagnostic.code}-${index}`}><span className="font-monospace">{diagnostic.code}</span>: {diagnostic.message}</li>)}</ul></Alert>}<Table responsive size="sm"><thead><tr><th>Step</th><th>Action</th><th>Effect</th></tr></thead><tbody>{plan.steps.map((step) => <tr key={step.id}><td>{step.id}</td><td>{step.action}</td><td>{step.effect || "-"}</td></tr>)}</tbody></Table><Button onClick={() => void applyPlan()} disabled={!canManage || !plan.steps.length || Boolean(busy)}>{busy === "apply" && <Spinner size="sm" className="me-2" />}<FontAwesomeIcon icon={faCheck} className="me-2" />Apply plan</Button></div>}
      </Card.Body></Card>

      <Card className="mb-4"><Card.Header>Observations: health, metrics, logs and alerts</Card.Header><Card.Body><ObservationTable observations={observations} /></Card.Body></Card>

      <Card><Card.Header>Operations and recovery</Card.Header><Card.Body>
        {!operations.length ? <p className="text-muted mb-0">No operations have been recorded.</p> : <Table responsive hover size="sm" className="align-middle mb-0"><thead><tr><th>Operation</th><th>Capability</th><th>State</th><th>Updated</th><th>Message</th><th className="text-end">Actions</th></tr></thead><tbody>{operations.map((operation) => <tr key={operation.id}><td className="font-monospace">{operation.id}</td><td>{operation.capability}</td><td><Badge bg={operationStateVariant(operation.state)}>{operation.state}</Badge></td><td>{timestamp(operation.updatedAt || operation.startedAt)}</td><td>{operation.message || "-"}</td><td className="text-end"><Button size="sm" variant="outline-danger" className="me-2" disabled={!canManage || Boolean(busy) || ["SUCCEEDED", "COMPLETED", "CANCELLED"].includes(operation.state)} onClick={() => void mutateOperation(operation, "cancel")}><FontAwesomeIcon icon={faBan} className="me-1" />Cancel</Button>{operation.recoveryActions.length > 0 && <Button size="sm" variant="outline-primary" disabled={!canManage || Boolean(busy)} onClick={() => void mutateOperation(operation, "recover")}>Recover</Button>}</td></tr>)}</tbody></Table>}
      </Card.Body></Card>
    </main>
  );
}
