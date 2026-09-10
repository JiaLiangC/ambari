<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# R1 Local Improvement: Authoring Validator

Base: local M2 candidate `b72ade8fcfd553ff182f3d34fe63c0903616005a`.

The new `mpack-authoring` module implements the first machine-readable authoring
boundary from `manifest-spec.md`: v2alpha1/kind detection, package and runtime
identity validation, artifact source/path containment, duplicate service and
component rejection, runtime adapter/version and capability declarations,
cardinality checks, and deterministic canonical SHA-256 content identity. A
small CLI emits a machine-readable validity/digest result and performs no
deployment or registration.

Focused tests are included under `mpack-authoring/src/test/python`. Validation
will be run with the rest of the local improvement batch after the current
implementation topics are complete.
