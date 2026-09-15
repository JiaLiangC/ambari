#!/usr/bin/env python3
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


import os
import unittest
from unittest.mock import patch
from acceptance import Client, AcceptanceFailure, main


class AcceptanceHarnessTest(unittest.TestCase):
  def test_changes_require_explicit_disposable_flag(self):
    with patch("acceptance.Client") as client:
      self.assertEqual(2, main(["--api-url", "http://localhost", "--cluster", "fixture", "--host", "host", "--package", "/missing", "--service", "FIXTURE"]))
      client.assert_not_called()

  def test_remote_plaintext_transport_and_missing_request_identity_fail_closed(self):
    with self.assertRaises(AcceptanceFailure):
      Client("http://remote.invalid")
    with patch.dict(os.environ, {"AMBARI_USERNAME": "fixture", "AMBARI_PASSWORD": "synthetic-fixture"}):
      client = Client("http://localhost")
    with self.assertRaisesRegex(AcceptanceFailure, "MISSING_REQUEST_ID"):
      client.wait("/clusters/fixture", {})

  def test_lost_response_does_not_retry_mutation(self):
    with patch.dict(os.environ, {"AMBARI_USERNAME": "fixture", "AMBARI_PASSWORD": "synthetic-fixture"}):
      client = Client("http://localhost")
    with patch.object(client.opener, "open", side_effect=OSError("synthetic")) as request:
      with self.assertRaisesRegex(AcceptanceFailure, "OUTCOME_UNKNOWN"):
        client.request("POST", "/mpacks/imports", b"fixture")
      self.assertEqual(1, request.call_count)
