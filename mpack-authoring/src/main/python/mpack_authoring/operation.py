"""
Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.
"""

from dataclasses import asdict, dataclass

from .runtime import RuntimeContext


@dataclass(frozen=True)
class PlanStep:
  id: str
  action: str
  capability: str
  preconditions: tuple
  effects: tuple

  def as_dict(self):
    value = asdict(self)
    value["preconditions"] = list(self.preconditions)
    value["effects"] = list(self.effects)
    return value


def plan_operation(context: RuntimeContext, requested_steps):
  """Create an ordered, non-mutating plan for a scoped runtime context."""
  if not requested_steps:
    raise ValueError("At least one operation step is required")
  seen = set()
  result = []
  for index, requested in enumerate(requested_steps):
    if not isinstance(requested, dict):
      raise ValueError("Operation steps must be objects")
    action = requested.get("action")
    capability = requested.get("capability", action)
    if not isinstance(action, str) or not action.strip():
      raise ValueError("Operation step action is required")
    if not isinstance(capability, str) or not capability.strip():
      raise ValueError("Operation step capability is required")
    step_id = requested.get("id", "step-{}".format(index + 1))
    if step_id in seen:
      raise ValueError("Duplicate operation step {}".format(step_id))
    seen.add(step_id)
    context.require({capability})
    result.append(PlanStep(
      id=step_id,
      action=action,
      capability=capability,
      preconditions=("service_ref_exists", "package_digest_verified"),
      effects=("{}:requested".format(action),),
    ))
  return result
