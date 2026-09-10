<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# W1-B3 Blueprint and API Projection

Integrated package-aware advisor request/response resources, operating-system
metadata, and additive Blueprint `mpack_instances` projection through
`BlueprintResourceProvider`, `MpackReference`, and current REST resource
definitions. Existing `(cluster_id, service_name)` identity remains the
authority; generated ServiceGroup identities and same-cluster duplicate service
aliases are rejected.

Legacy Blueprints without package settings remain supported. Malformed or
unknown package references fail closed and are covered by the final focused
validation batch.
