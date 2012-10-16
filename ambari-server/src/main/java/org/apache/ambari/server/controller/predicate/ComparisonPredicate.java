/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ambari.server.controller.predicate;

import org.apache.ambari.server.controller.spi.PropertyId;
import org.apache.ambari.server.controller.spi.Resource;

/**
 * Predicate that compares a given value to a {@link Resource} property.
 */
public abstract class ComparisonPredicate<T> extends PropertyPredicate implements BasePredicate {
  private final Comparable<T> value;

  public ComparisonPredicate(PropertyId propertyId, Comparable<T> value) {
    super(propertyId);
    this.value = value;
  }

  public Comparable<T> getValue() {
    return value;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (!(o instanceof ComparisonPredicate)) return false;
    if (!super.equals(o)) return false;

    ComparisonPredicate that = (ComparisonPredicate) o;

    return !(value != null ? !value.equals(that.value) : that.value != null);
  }

  @Override
  public int hashCode() {
    int result = super.hashCode();
    result = 31 * result + (value != null ? value.hashCode() : 0);
    return result;
  }

  @Override
  public void accept(PredicateVisitor visitor) {
    visitor.acceptComparisonPredicate(this);
  }


  public abstract String getOperator();
}
