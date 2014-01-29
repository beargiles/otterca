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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Exception that bundles multiple errors into a single exception. A Map is used
 * instead of a Set in order to be able to provide additional details.
 * 
 * @author bgiles@otterca.com
 */
public class X509CertificateBuilderException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;
    private static final ErrorType[] errorTypeEmptyArray = new ErrorType[0];
    private final Map<ErrorType, String> errors = new HashMap<ErrorType, String>();

    // @formatter:off
    public enum ErrorType {
        MISSING_ISSUER_CERTIFICATE,
        MISSING_SERIAL_NUMBER,
        MISSING_SUBJECT_DN,
        MISSING_ISSUER_DN,
        MISSING_NOT_BEFORE_DATE,
        MISSING_NOT_AFTER_DATE,
        MISSING_PUBLIC_KEY,
        INVALID_ISSUER,
        ISSUER_CANNOT_SIGN_CERTIFICATES,
        UNACCEPTABLE_DATE_RANGE,
        UKNOWN_SUBJECT,
        UKNOWN_ISSUER,
        UNKNOWN_CERTIFICATE,
        MISSING_KEYSTORE,
        BAD_PATH_LENGTH_CONSTRAINT_WITH_BASIC_CONSTRAINT,
        PRIVATE_KEY_USAGE_PERIOD_VIOLATES_NOT_BEFORE,
        PRIVATE_KEY_USAGE_PERIOD_VIOLATES_NOT_AFTER,
        INHIBIT_ANY_POLICY_DEPTH_MUST_DECREASE,
        NEGATIVE_INHIBIT_ANY_POLICY_DEPTH,
        OTHER_ERROR
    };

    // @formatter:on

    /**
     * Default constructor.
     */
    public X509CertificateBuilderException() {

    }

    /**
     * Singleton constructor.
     */
    public X509CertificateBuilderException(ErrorType errorType) {
        errors.put(errorType, null);
    }

    /**
     * List constructor.
     */
    public X509CertificateBuilderException(List<ErrorType> errors) {
        for (ErrorType error : errors) {
            this.errors.put(error, null);
        }
    }

    /**
     * Did errors happen?
     * 
     * @return true if errors occurred.
     */
    public boolean hasErrors() {
        return !errors.isEmpty();
    }

    /**
     * Get the number of errors
     * 
     * @return the number of errors.
     */
    public int getErrorCount() {
        return errors.size();
    }

    /**
     * Get the errors.
     * 
     * @return
     */
    public Map<ErrorType, String> getErrors() {
        return Collections.unmodifiableMap(errors);
    }

    /**
     * Add an error
     */
    public void addError(ErrorType errorType) {
        errors.put(errorType, null);
    }

    /**
     * Add an error
     */
    public void addError(ErrorType errorType, String details) {
        errors.put(errorType, details);
    }

    /**
     * Merge error lists
     */
    public void addAll(X509CertificateBuilderException ex) {
        errors.putAll(ex.errors);
    }

    /**
     * @see java.lang.Exception#getMessage()
     */
    @Override
    public String getMessage() {
        return "Error(s) with certificate builder arguments: "
                + Arrays.toString(errors.keySet().toArray(errorTypeEmptyArray));
    }
}