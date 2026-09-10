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

import { useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  Alert,
  Badge,
  Button,
  ButtonGroup,
  Col,
  Form,
  InputGroup,
  Modal,
  OverlayTrigger,
  Row,
  Spinner as BootstrapSpinner,
  Table,
  Tooltip,
} from "react-bootstrap";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faArrowLeft,
  faCheck,
  faDownload,
  faGaugeHigh,
  faHardDrive,
  faLink,
  faPen,
  faPlus,
  faRotate,
  faSearch,
  faTrash,
} from "@fortawesome/free-solid-svg-icons";
import toast from "react-hot-toast";
import { useNavigate } from "react-router-dom";
import MpackApi, { RegistryDefinition } from "../../api/mpacksApi";
import { AppContext } from "../../store/context";
import { useAuth } from "../../hooks/useAuth";
import Spinner from "../../components/Spinner";
import {
  CatalogMpackVersion,
  catalogKey,
  normalizeOperatingSystems,
  normalizeRecommendedBundle,
  normalizeRegisteredMpacks,
  normalizeRegistries,
  normalizeValidationResults,
  OperatingSystemMetadata,
  redactUri,
  RegisteredMpack,
  RegistryCatalog,
  selectionSignature,
  ValidationResult,
} from "./model";

type RegistryEditor = {
  id?: number;
  name: string;
  uri: string;
};

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

function dependencyLabel(dependency: CatalogMpackVersion["dependencies"][number]) {
  if (!dependency.minVersion && !dependency.maxVersion) return dependency.name;
  const lower = dependency.minVersion ? `[${dependency.minVersion}` : "unbounded";
  const upper = dependency.maxVersion ? `${dependency.maxVersion})` : "unbounded";
  return `${dependency.name} ${lower}, ${upper}`;
}

function ActionButton({
  disabled,
  icon,
  label,
  onClick,
  variant = "outline-secondary",
}: {
  disabled?: boolean;
  icon: typeof faPlus;
  label: string;
  onClick: () => void;
  variant?: string;
}) {
  return (
    <OverlayTrigger placement="top" overlay={<Tooltip>{label}</Tooltip>}>
      <span>
        <Button
          aria-label={label}
          disabled={disabled}
          onClick={onClick}
          size="sm"
          variant={variant}
        >
          <FontAwesomeIcon icon={icon} />
        </Button>
      </span>
    </OverlayTrigger>
  );
}

export default function ManagementPacks() {
  const navigate = useNavigate();
  const { hasAuthorization } = useAuth();
  const {
    clusterName,
    isClusterInstalled,
    isNonWizardUser,
    upgradeIsRunning,
  } = useContext(AppContext);
  const [registries, setRegistries] = useState<RegistryCatalog[]>([]);
  const [installed, setInstalled] = useState<RegisteredMpack[]>([]);
  const [selectedRegistryId, setSelectedRegistryId] = useState<number>();
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [selectedScenario, setSelectedScenario] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");
  const [operationError, setOperationError] = useState("");
  const [busy, setBusy] = useState("");
  const [registryEditor, setRegistryEditor] = useState<RegistryEditor>();
  const [registryToDelete, setRegistryToDelete] = useState<RegistryCatalog>();
  const [directUri, setDirectUri] = useState<string>();
  const [showInstallConfirmation, setShowInstallConfirmation] = useState(false);
  const [mpackToDelete, setMpackToDelete] = useState<RegisteredMpack>();
  const [osDialog, setOsDialog] = useState<{
    mpack: RegisteredMpack;
    items: OperatingSystemMetadata[];
    loading: boolean;
    error: string;
  }>();
  const [validation, setValidation] = useState<{
    signature: string;
    results: ValidationResult[];
  }>();
  const [recommendationNotice, setRecommendationNotice] = useState("");
  const loadGeneration = useRef(0);

  const canManage = hasAuthorization("AMBARI.MANAGE_STACK_VERSIONS");
  const mutationBlocked = upgradeIsRunning || isNonWizardUser;
  const canMutate = canManage && !mutationBlocked;

  const load = useCallback(async () => {
    const generation = ++loadGeneration.current;
    setLoading(true);
    setLoadError("");
    try {
      const [registryResponse, installedResponse] = await Promise.all([
        MpackApi.getRegistries(),
        MpackApi.getRegisteredMpacks(),
      ]);
      if (generation !== loadGeneration.current) return;
      const nextRegistries = normalizeRegistries(registryResponse);
      setRegistries(nextRegistries);
      setInstalled(normalizeRegisteredMpacks(installedResponse));
      setSelectedRegistryId((current) => (
        current && nextRegistries.some((registry) => registry.id === current)
          ? current
          : nextRegistries[0]?.id
      ));
    } catch (error) {
      if (generation === loadGeneration.current) {
        setLoadError(errorMessage(error, "Management pack data could not be loaded."));
      }
    } finally {
      if (generation === loadGeneration.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    return () => {
      loadGeneration.current += 1;
    };
  }, [load]);

  const activeRegistry = registries.find((registry) => registry.id === selectedRegistryId);
  const visibleVersions = useMemo(() => {
    const query = search.trim().toLowerCase();
    return (activeRegistry?.versions || []).filter((version) => !query || [
      version.name,
      version.displayName,
      version.description,
      version.version,
      ...version.modules.flatMap((module) => [module.name, module.displayName]),
    ].some((value) => value.toLowerCase().includes(query)));
  }, [activeRegistry, search]);
  const selectedVersions = useMemo(() => (
    (activeRegistry?.versions || []).filter((version) => selectedKeys.has(catalogKey(version)))
  ), [activeRegistry, selectedKeys]);
  const currentSignature = selectionSignature(selectedVersions);
  const validationCurrent = validation?.signature === currentSignature;
  const validationPassed = validationCurrent
    && validation.results.every((result) => result.level.toUpperCase() !== "FATAL");

  function resetSelection() {
    setSelectedKeys(new Set());
    setValidation(undefined);
    setRecommendationNotice("");
  }

  function switchRegistry(value: string) {
    setSelectedRegistryId(Number(value));
    setSelectedScenario("");
    setSearch("");
    resetSelection();
  }

  function toggleVersion(version: CatalogMpackVersion) {
    const key = catalogKey(version);
    setSelectedKeys((current) => {
      const next = new Set(current);
      if (next.has(key)) {
        next.delete(key);
      } else {
        for (const candidate of activeRegistry?.versions || []) {
          if (candidate.name === version.name) next.delete(catalogKey(candidate));
        }
        next.add(key);
      }
      return next;
    });
    setValidation(undefined);
    setRecommendationNotice("");
  }

  function isInstalled(version: CatalogMpackVersion) {
    return installed.some((mpack) => mpack.name === version.name
      && mpack.version === version.version);
  }

  async function validateSelected() {
    if (!activeRegistry || !selectedVersions.length) return;
    setBusy("validate");
    setOperationError("");
    try {
      const response = await MpackApi.validateSelection(
        activeRegistry.id,
        selectedVersions.map((version) => ({
          mpack_name: version.name,
          mpack_version: version.version,
        })),
      );
      const results = normalizeValidationResults(response);
      setValidation({ signature: currentSignature, results });
      if (!results.length) toast.success("The selected management packs are compatible.");
    } catch (error) {
      setOperationError(errorMessage(error, "The management pack selection could not be validated."));
    } finally {
      setBusy("");
    }
  }

  async function recommendScenario() {
    if (!activeRegistry || !selectedScenario) return;
    setBusy("recommend");
    setOperationError("");
    try {
      const response = await MpackApi.recommendScenario(activeRegistry.id, selectedScenario);
      const recommendation = normalizeRecommendedBundle(response);
      if (!recommendation.mpacks.length) {
        throw new Error("No compatible management pack set is available for this scenario.");
      }
      const keys = new Set<string>();
      for (const recommended of recommendation.mpacks) {
        const match = activeRegistry.versions.find((version) => (
          version.name === recommended.name && version.version === recommended.version
        ));
        if (!match) {
          throw new Error(`Recommended management pack ${recommended.name}-${recommended.version} is not in the loaded catalog.`);
        }
        keys.add(catalogKey(match));
      }
      setSelectedKeys(keys);
      setValidation(undefined);
      setRecommendationNotice(
        recommendation.alternatives === 1
          ? "Selected the recommended compatible set."
          : `Selected the highest-ranked compatible set from ${recommendation.alternatives} alternatives.`,
      );
    } catch (error) {
      setOperationError(errorMessage(error, "A scenario recommendation could not be loaded."));
    } finally {
      setBusy("");
    }
  }

  async function installSelected() {
    if (!activeRegistry || !validationPassed) return;
    setShowInstallConfirmation(false);
    setBusy("install");
    setOperationError("");
    try {
      for (const version of [...selectedVersions].sort((left, right) => (
        left.name.localeCompare(right.name) || left.version.localeCompare(right.version)
      ))) {
        if (isInstalled(version)) continue;
        await MpackApi.registerFromRegistry(
          activeRegistry.id,
          version.name,
          version.version,
        );
      }
      toast.success("Management packs registered successfully.");
      resetSelection();
      await load();
    } catch (error) {
      setOperationError(errorMessage(
        error,
        "Management pack registration stopped after a failure. Completed registrations were retained.",
      ));
      await load();
    } finally {
      setBusy("");
    }
  }

  async function saveRegistry() {
    if (!registryEditor?.name.trim() || !registryEditor.uri.trim()) return;
    setBusy("registry");
    setOperationError("");
    const definition: RegistryDefinition = {
      name: registryEditor.name.trim(),
      type: "JSON",
      uri: registryEditor.uri.trim(),
    };
    try {
      if (registryEditor.id === undefined) {
        await MpackApi.createRegistry(definition);
      } else {
        await MpackApi.updateRegistry(registryEditor.id, definition);
      }
      setRegistryEditor(undefined);
      toast.success("Software registry saved successfully.");
      await load();
    } catch (error) {
      setOperationError(errorMessage(error, "The software registry could not be saved."));
    } finally {
      setBusy("");
    }
  }

  async function deleteRegistry() {
    if (!registryToDelete) return;
    setBusy("registry-delete");
    setOperationError("");
    try {
      await MpackApi.deleteRegistry(registryToDelete.id);
      setRegistryToDelete(undefined);
      toast.success("Software registry removed successfully.");
      resetSelection();
      await load();
    } catch (error) {
      setOperationError(errorMessage(error, "The software registry could not be removed."));
    } finally {
      setBusy("");
    }
  }

  async function registerDirectUri() {
    if (!directUri?.trim()) return;
    setBusy("direct");
    setOperationError("");
    try {
      await MpackApi.registerFromUri(directUri.trim());
      setDirectUri(undefined);
      toast.success("Management pack registered successfully.");
      await load();
    } catch (error) {
      setOperationError(errorMessage(error, "The management pack could not be registered."));
    } finally {
      setBusy("");
    }
  }

  async function deleteMpack() {
    if (!mpackToDelete) return;
    setBusy("mpack-delete");
    setOperationError("");
    try {
      await MpackApi.deleteMpack(mpackToDelete.id);
      setMpackToDelete(undefined);
      toast.success("Management pack removed successfully.");
      await load();
    } catch (error) {
      setOperationError(errorMessage(error, "The management pack could not be removed."));
    } finally {
      setBusy("");
    }
  }

  async function showOperatingSystems(mpack: RegisteredMpack) {
    setOsDialog({ mpack, items: [], loading: true, error: "" });
    try {
      const response = await MpackApi.getOperatingSystems(mpack.id);
      setOsDialog({
        mpack,
        items: normalizeOperatingSystems(response),
        loading: false,
        error: "",
      });
    } catch (error) {
      setOsDialog({
        mpack,
        items: [],
        loading: false,
        error: errorMessage(error, "Repository metadata could not be loaded."),
      });
    }
  }

  if (loading && !registries.length && !installed.length) return <Spinner />;

  return (
    <main className="container-fluid px-4 py-4">
      <div className="d-flex flex-wrap align-items-center justify-content-between gap-3 mb-4">
        <div className="d-flex align-items-center gap-3">
          <ActionButton
            icon={faArrowLeft}
            label="Back"
            onClick={() => navigate(
              isClusterInstalled
                ? "/main/admin/stack/services"
                : clusterName ? "/installer/step0" : "/adminView",
            )}
          />
          <h2 className="mb-0">Management Packs</h2>
        </div>
        <ButtonGroup>
          <Button onClick={() => void load()} variant="outline-secondary" disabled={loading || Boolean(busy)}>
            <FontAwesomeIcon icon={faRotate} className="me-2" />
            Refresh
          </Button>
          {canManage && (
            <>
              <Button
                onClick={() => setRegistryEditor({ name: "", uri: "" })}
                disabled={!canMutate || Boolean(busy)}
                variant="outline-primary"
              >
                <FontAwesomeIcon icon={faPlus} className="me-2" />
                Add Registry
              </Button>
              <Button
                onClick={() => setDirectUri("")}
                disabled={!canMutate || Boolean(busy)}
                variant="primary"
              >
                <FontAwesomeIcon icon={faLink} className="me-2" />
                Register URI
              </Button>
            </>
          )}
        </ButtonGroup>
      </div>

      {loadError && (
        <Alert variant="danger" className="d-flex justify-content-between align-items-center">
          <span>{loadError}</span>
          <Button variant="outline-danger" size="sm" onClick={() => void load()}>Retry</Button>
        </Alert>
      )}
      {operationError && (
        <Alert variant="danger" dismissible onClose={() => setOperationError("")}>
          {operationError}
        </Alert>
      )}
      {canManage && mutationBlocked && (
        <Alert variant="warning">
          Management pack changes are unavailable while another owned workflow or an upgrade is active.
        </Alert>
      )}

      <section className="mb-5" aria-labelledby="registries-heading">
        <h3 id="registries-heading" className="h5 mb-3">Software Registries</h3>
        {registries.length ? (
          <Table responsive hover className="align-middle">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Packages</th>
                <th>Scenarios</th>
                {canManage && <th className="text-end">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {registries.map((registry) => (
                <tr key={registry.id}>
                  <td>{registry.name}</td>
                  <td>{registry.type}</td>
                  <td>{new Set(registry.versions.map((version) => version.name)).size}</td>
                  <td>{registry.scenarios.length}</td>
                  {canManage && (
                    <td className="text-end">
                      <ButtonGroup>
                        <ActionButton
                          disabled={!canMutate || Boolean(busy)}
                          icon={faPen}
                          label={`Replace ${registry.name}`}
                          onClick={() => setRegistryEditor({
                            id: registry.id,
                            name: registry.name,
                            uri: "",
                          })}
                        />
                        <ActionButton
                          disabled={!canMutate || Boolean(busy)}
                          icon={faTrash}
                          label={`Remove ${registry.name}`}
                          onClick={() => setRegistryToDelete(registry)}
                          variant="outline-danger"
                        />
                      </ButtonGroup>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        ) : !loadError && <p className="text-muted">No software registries are configured.</p>}
      </section>

      <section className="mb-5" aria-labelledby="catalog-heading">
        <div className="d-flex flex-wrap align-items-end justify-content-between gap-3 mb-3">
          <div>
            <h3 id="catalog-heading" className="h5 mb-2">Catalog</h3>
            <Form.Select
              aria-label="Software registry"
              value={selectedRegistryId ?? ""}
              onChange={(event) => switchRegistry(event.target.value)}
              style={{ minWidth: 240 }}
              disabled={!registries.length || Boolean(busy)}
            >
              {!registries.length && <option value="">No registries</option>}
              {registries.map((registry) => (
                <option key={registry.id} value={registry.id}>{registry.name}</option>
              ))}
            </Form.Select>
          </div>
          <InputGroup style={{ maxWidth: 360 }}>
            <InputGroup.Text><FontAwesomeIcon icon={faSearch} /></InputGroup.Text>
            <Form.Control
              aria-label="Search catalog"
              placeholder="Search packages or modules"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </InputGroup>
        </div>

        {activeRegistry?.scenarios.length ? (
          <Row className="align-items-end g-2 mb-3">
            <Col md={5} lg={4}>
              <Form.Label>Scenario</Form.Label>
              <Form.Select
                value={selectedScenario}
                onChange={(event) => setSelectedScenario(event.target.value)}
                disabled={Boolean(busy)}
              >
                <option value="">Select a scenario</option>
                {activeRegistry.scenarios.map((scenario) => (
                  <option key={scenario.name} value={scenario.name}>{scenario.name}</option>
                ))}
              </Form.Select>
            </Col>
            <Col xs="auto">
              <Button
                variant="outline-primary"
                disabled={!selectedScenario || Boolean(busy)}
                onClick={() => void recommendScenario()}
              >
                Recommend Set
              </Button>
            </Col>
          </Row>
        ) : null}

        {recommendationNotice && <Alert variant="info">{recommendationNotice}</Alert>}
        {validationCurrent && (
          validation.results.length ? (
            <Alert variant="danger">
              <Alert.Heading className="h6">Compatibility issues</Alert.Heading>
              <ul className="mb-0">
                {validation.results.map((result, index) => (
                  <li key={`${result.type}-${index}`}>{result.message}</li>
                ))}
              </ul>
            </Alert>
          ) : (
            <Alert variant="success">
              <FontAwesomeIcon icon={faCheck} className="me-2" />
              Selection is compatible.
            </Alert>
          )
        )}

        {visibleVersions.length ? (
          <Table responsive hover className="align-middle">
            <thead>
              <tr>
                <th style={{ width: 44 }}><span className="visually-hidden">Select</span></th>
                <th>Management Pack</th>
                <th>Version</th>
                <th>Modules</th>
                <th>Dependencies</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {visibleVersions.map((version) => {
                const installedExact = isInstalled(version);
                const key = catalogKey(version);
                return (
                  <tr key={key}>
                    <td>
                      <Form.Check
                        aria-label={`Select ${version.name} ${version.version}`}
                        checked={selectedKeys.has(key)}
                        disabled={installedExact || !canMutate || Boolean(busy)}
                        onChange={() => toggleVersion(version)}
                      />
                    </td>
                    <td>
                      <div className="fw-semibold">{version.displayName}</div>
                      <div className="small text-muted">{version.name}</div>
                      {version.description && <div className="small mt-1">{version.description}</div>}
                    </td>
                    <td>{version.version}</td>
                    <td>
                      {version.modules.length
                        ? version.modules.map((module) => module.displayName).join(", ")
                        : <span className="text-muted">None</span>}
                    </td>
                    <td>
                      {version.dependencies.length
                        ? version.dependencies.map(dependencyLabel).join("; ")
                        : <span className="text-muted">None</span>}
                    </td>
                    <td>
                      {installedExact
                        ? <Badge bg="success">Registered</Badge>
                        : installed.some((mpack) => mpack.name === version.name)
                          ? <Badge bg="warning" text="dark">Other version registered</Badge>
                          : <Badge bg="secondary">Available</Badge>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        ) : activeRegistry && <p className="text-muted">No matching management packs.</p>}

        <div className="d-flex flex-wrap justify-content-end gap-2">
          <Button
            variant="outline-primary"
            disabled={!selectedVersions.length || Boolean(busy)}
            onClick={() => void validateSelected()}
          >
            {busy === "validate" && <BootstrapSpinner size="sm" className="me-2" />}
            Check Compatibility
          </Button>
          {canManage && (
            <Button
              disabled={!canMutate || !validationPassed || Boolean(busy)}
              onClick={() => setShowInstallConfirmation(true)}
            >
              <FontAwesomeIcon icon={faDownload} className="me-2" />
              Register Selected ({selectedVersions.filter((version) => !isInstalled(version)).length})
            </Button>
          )}
        </div>
      </section>

      <section aria-labelledby="installed-heading">
        <h3 id="installed-heading" className="h5 mb-3">Registered Management Packs</h3>
        {installed.length ? (
          <Table responsive hover className="align-middle">
            <thead>
              <tr>
                <th>Management Pack</th>
                <th>Version</th>
                <th>Modules</th>
                <th>Source</th>
                <th className="text-end">Actions</th>
              </tr>
            </thead>
            <tbody>
              {installed.map((mpack) => (
                <tr key={mpack.id}>
                  <td>
                    <div className="fw-semibold">{mpack.displayName}</div>
                    <div className="small text-muted">{mpack.name}</div>
                  </td>
                  <td>{mpack.version}</td>
                  <td>{mpack.modules.map((module) => module.displayName).join(", ") || "None"}</td>
                  <td>{registries.find((registry) => registry.id === mpack.registryId)?.name || "Direct URI"}</td>
                  <td className="text-end">
                    <ButtonGroup>
                      <ActionButton
                        icon={faHardDrive}
                        label={`Repository metadata for ${mpack.name}`}
                        onClick={() => void showOperatingSystems(mpack)}
                      />
                      <ActionButton
                        icon={faGaugeHigh}
                        label={`Runtime details for ${mpack.name}`}
                        onClick={() => navigate(`/main/admin/mpacks/${mpack.id}/runtime`)}
                      />
                      {canManage && (
                        <ActionButton
                          disabled={!canMutate || Boolean(busy)}
                          icon={faTrash}
                          label={`Remove ${mpack.name} ${mpack.version}`}
                          onClick={() => setMpackToDelete(mpack)}
                          variant="outline-danger"
                        />
                      )}
                    </ButtonGroup>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : <p className="text-muted">No management packs are registered.</p>}
      </section>

      <Modal show={registryEditor !== undefined} onHide={() => !busy && setRegistryEditor(undefined)}>
        <Modal.Header closeButton={!busy}>
          <Modal.Title>{registryEditor?.id === undefined ? "Add Registry" : "Replace Registry"}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <Form.Group className="mb-3">
            <Form.Label>Name</Form.Label>
            <Form.Control
              value={registryEditor?.name || ""}
              onChange={(event) => setRegistryEditor((current) => current && ({
                ...current,
                name: event.target.value,
              }))}
              disabled={Boolean(busy)}
            />
          </Form.Group>
          <Form.Group className="mb-3">
            <Form.Label>Type</Form.Label>
            <Form.Select value="JSON" disabled><option>JSON</option></Form.Select>
          </Form.Group>
          <Form.Group>
            <Form.Label>{registryEditor?.id === undefined ? "Registry URI" : "Replacement Registry URI"}</Form.Label>
            <Form.Control
              value={registryEditor?.uri || ""}
              onChange={(event) => setRegistryEditor((current) => current && ({
                ...current,
                uri: event.target.value,
              }))}
              disabled={Boolean(busy)}
              autoComplete="off"
            />
          </Form.Group>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setRegistryEditor(undefined)} disabled={Boolean(busy)}>Cancel</Button>
          <Button
            onClick={() => void saveRegistry()}
            disabled={!registryEditor?.name.trim() || !registryEditor.uri.trim() || Boolean(busy)}
          >
            {busy === "registry" && <BootstrapSpinner size="sm" className="me-2" />}
            Save
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal show={directUri !== undefined} onHide={() => !busy && setDirectUri(undefined)}>
        <Modal.Header closeButton={!busy}><Modal.Title>Register Management Pack</Modal.Title></Modal.Header>
        <Modal.Body>
          <Form.Group>
            <Form.Label>Management Pack URI</Form.Label>
            <Form.Control
              value={directUri || ""}
              onChange={(event) => setDirectUri(event.target.value)}
              disabled={Boolean(busy)}
              autoComplete="off"
            />
          </Form.Group>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setDirectUri(undefined)} disabled={Boolean(busy)}>Cancel</Button>
          <Button onClick={() => void registerDirectUri()} disabled={!directUri?.trim() || Boolean(busy)}>
            {busy === "direct" && <BootstrapSpinner size="sm" className="me-2" />}
            Register
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal show={showInstallConfirmation} onHide={() => setShowInstallConfirmation(false)}>
        <Modal.Header closeButton><Modal.Title>Register Selected Management Packs</Modal.Title></Modal.Header>
        <Modal.Body>
          <ul className="mb-0">
            {selectedVersions.filter((version) => !isInstalled(version)).map((version) => (
              <li key={catalogKey(version)}>{version.name} {version.version}</li>
            ))}
          </ul>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowInstallConfirmation(false)}>Cancel</Button>
          <Button onClick={() => void installSelected()}>Register</Button>
        </Modal.Footer>
      </Modal>

      <Modal show={registryToDelete !== undefined} onHide={() => !busy && setRegistryToDelete(undefined)}>
        <Modal.Header closeButton={!busy}><Modal.Title>Remove Software Registry</Modal.Title></Modal.Header>
        <Modal.Body>Remove {registryToDelete?.name}?</Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setRegistryToDelete(undefined)} disabled={Boolean(busy)}>Cancel</Button>
          <Button variant="danger" onClick={() => void deleteRegistry()} disabled={Boolean(busy)}>
            {busy === "registry-delete" && <BootstrapSpinner size="sm" className="me-2" />}
            Remove
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal show={mpackToDelete !== undefined} onHide={() => !busy && setMpackToDelete(undefined)}>
        <Modal.Header closeButton={!busy}><Modal.Title>Remove Management Pack</Modal.Title></Modal.Header>
        <Modal.Body>
          Remove {mpackToDelete?.name} {mpackToDelete?.version}?
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setMpackToDelete(undefined)} disabled={Boolean(busy)}>Cancel</Button>
          <Button variant="danger" onClick={() => void deleteMpack()} disabled={Boolean(busy)}>
            {busy === "mpack-delete" && <BootstrapSpinner size="sm" className="me-2" />}
            Remove
          </Button>
        </Modal.Footer>
      </Modal>

      <Modal show={osDialog !== undefined} onHide={() => setOsDialog(undefined)} size="lg">
        <Modal.Header closeButton><Modal.Title>Repository Metadata</Modal.Title></Modal.Header>
        <Modal.Body>
          {osDialog?.loading ? <Spinner /> : osDialog?.error ? (
            <Alert variant="danger">{osDialog.error}</Alert>
          ) : osDialog?.items.length ? (
            <Table responsive size="sm">
              <thead><tr><th>Operating System</th><th>Repository</th><th>Base URL</th></tr></thead>
              <tbody>
                {osDialog.items.flatMap((operatingSystem) => (
                  operatingSystem.repositories.length
                    ? operatingSystem.repositories.map((repository, index) => (
                        <tr key={`${operatingSystem.osType}-${repository.id}-${index}`}>
                          <td>{operatingSystem.osType}</td>
                          <td>{repository.name || repository.id}</td>
                          <td className="text-break">{redactUri(repository.baseUrl)}</td>
                        </tr>
                      ))
                    : [(
                        <tr key={operatingSystem.osType}>
                          <td>{operatingSystem.osType}</td><td colSpan={2}>No repositories</td>
                        </tr>
                      )]
                ))}
              </tbody>
            </Table>
          ) : <p className="text-muted mb-0">No operating-system repository metadata.</p>}
        </Modal.Body>
        <Modal.Footer><Button variant="secondary" onClick={() => setOsDialog(undefined)}>Close</Button></Modal.Footer>
      </Modal>
    </main>
  );
}
