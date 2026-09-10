<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# W1-B2 Registry and Catalog

Integrated registry persistence, JSON loading, relative URI resolution,
catalog mpack/version/scenario resources, deterministic recommendations and
validation, and typed failure handling. Main paths are
`ambari-server/src/main/java/org/apache/ambari/server/registry`, the registry
controller providers, resource definitions, DAOs/entities, and
`UpgradeCatalog310.java`.

The catalog remains advisory metadata. It does not own cluster identity,
service identity, dependency bindings, or deployment state. Remote registries
are constrained to the documented URI policy and local deterministic fixtures
are required for final validation.

Validation is deferred until all W1 implementation batches are complete.
