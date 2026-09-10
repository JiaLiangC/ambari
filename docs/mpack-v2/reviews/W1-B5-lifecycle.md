<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# W1-B5 Lifecycle and Persistence

Integrated package metadata, repository/OS projection, persistence mappings,
fresh DDL, and the `UpgradeCatalog310` migration path while retaining current
repository catalogs, upgrade providers, and install ownership. Publication and
deletion paths use rollback/locking checks and preserve existing stack
metadata.

Fresh-schema and existing-database migration checks are deferred until all W1
implementation work is complete.
