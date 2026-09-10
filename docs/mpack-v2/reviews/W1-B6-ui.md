<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# W1-B6 Package Administration UI

Integrated API-backed management-pack catalog, registry, registration,
validation/recommendation, operating-system metadata, and removal flows into
the current Classic admin route and React admin route. Permissions use existing
stack-detail and stack-version administration roles, and package actions retain
current cluster/workflow ownership.

The Classic implementation follows the active Ember source and the React
implementation uses a tolerant response model for Ambari resource nesting.
Frontend build, browser, stale-response, and failure-recovery checks are
deferred until the implementation batches are complete.
