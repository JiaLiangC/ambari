"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from .manifest import ManifestError, load_manifest, validate_manifest
from .build import build_lock, write_lock
from .runtime import ServiceRef
from .diagnostics import Diagnostic, compile_with_diagnostics, make_diagnostic, validate_with_diagnostics
from .config import ConfigValue, SecretRef, effective_config
from .dependency import BindingSnapshot, DependencyAdapter, DependencyRequirement
from .conformance import validate_fixture_directory
from .compiler import CompileError, build_package, compile_manifest, load_source, legacy_projection, sign_bytes, verify_package
from .legacy import export_legacy

__all__ = ["BindingSnapshot", "ConfigValue", "DependencyAdapter", "DependencyRequirement",
           "Diagnostic", "ManifestError", "SecretRef", "ServiceRef", "make_diagnostic",
           "validate_fixture_directory", "build_lock", "load_manifest", "validate_manifest",
           "validate_with_diagnostics", "compile_with_diagnostics", "CompileError", "build_package",
           "compile_manifest", "load_source", "legacy_projection", "sign_bytes", "verify_package",
           "effective_config", "write_lock", "export_legacy"]
