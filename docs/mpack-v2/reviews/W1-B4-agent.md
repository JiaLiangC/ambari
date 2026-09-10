<!-- Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright ownership. The ASF licenses this file under the Apache License, Version 2.0. -->

# W1-B4 Agent and Instance Manager

Integrated additive package context in execution commands and component version
reporting, Python 3 package helpers, and the `mpack-instance-manager` module
with configured roots and RPM/DEB lifecycle scriptlets. Existing command
fields and legacy install actions remain readable.

The final validation must cover old payloads with absent package fields, new
multi-package payloads, CLI JSON output, and package contents. Host RPM tooling
is unavailable, so source and tar/DEB checks are the available packaging
evidence until a builder is supplied.
