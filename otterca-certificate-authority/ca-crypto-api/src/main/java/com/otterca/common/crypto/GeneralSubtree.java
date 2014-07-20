/*
 * This code was written by Bear Giles <bgiles@otterca.com>and he
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Any contributions made by others are licensed to this project under
 * one or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * 
 * Copyright (c) 2012 Bear Giles <bgiles@otterca.com>
 */
package com.otterca.common.crypto;

import java.math.BigInteger;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.security.auth.x500.X500Principal;

/**
 * Enclosure for X509 'GeneralSubtree' values. This is used to specify Name
 * Constraints.
 * 
 * @author bgiles@otterca.com
 */
@ParametersAreNonnullByDefault
public class GeneralSubtree {
    private X500Principal name;
    private BigInteger min;
    private BigInteger max;

    public GeneralSubtree() {

    }

    public GeneralSubtree(X500Principal name) {
        this.name = name;
    }

    public GeneralSubtree(X500Principal name, BigInteger min, BigInteger max) {
        this.name = name;
        this.min = min;
        this.max = max;
    }

    /**
     * @return the name
     */
    public X500Principal getName() {
        return name;
    }

    /**
     * @param name
     *            the name to set
     */
    public void setName(X500Principal name) {
        this.name = name;
    }

    /**
     * @return the min
     */
    public BigInteger getMin() {
        return min;
    }

    /**
     * @param min
     *            the min to set
     */
    public void setMin(BigInteger min) {
        this.min = min;
    }

    /**
     * @return the max
     */
    public BigInteger getMax() {
        return max;
    }

    /**
     * @param max
     *            the max to set
     */
    public void setMax(BigInteger max) {
        this.max = max;
    }

    /**
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("GeneralSubtree[");
        sb.append((name != null) ? "'" + name.getName() + "'" : "(null)");
        sb.append(", ");
        sb.append((min != null) ? min.toString() : "*");
        sb.append(", ");
        sb.append((max != null) ? max.toString() : "*");
        sb.append("]");
        return sb.toString();
    }
}
