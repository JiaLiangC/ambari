"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandSpec:
  program: str
  arguments: tuple = ()

  def argv(self):
    return (self.program,) + tuple(self.arguments)


class ExecutionResult:
  def __init__(self, state, output="", error=""):
    self.state = state
    self.output = output
    self.error = error


class DryRunExecutor:
  """Safe executor used by plans; it never starts a process."""

  def run(self, command, idempotency_key):
    if not isinstance(command, CommandSpec) or not idempotency_key:
      raise ValueError("CommandSpec and idempotency key are required")
    return ExecutionResult("PLANNED", " ".join(command.argv()))


class InjectedExecutor:
  """Adapter boundary for an explicitly supplied policy-owned executor."""

  def __init__(self, runner):
    if not callable(runner):
      raise ValueError("runner must be callable")
    self.runner = runner

  def run(self, command, idempotency_key):
    if not isinstance(command, CommandSpec) or not idempotency_key:
      raise ValueError("CommandSpec and idempotency key are required")
    try:
      return ExecutionResult("SUCCEEDED", self.runner(command.argv(), idempotency_key))
    except TimeoutError as error:
      return ExecutionResult("UNKNOWN", error=str(error))
