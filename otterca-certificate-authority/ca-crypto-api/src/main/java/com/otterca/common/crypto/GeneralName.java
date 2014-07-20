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

import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;

/**
 * Enclosure for X509 'GeneralName' values.
 * 
 * @author bgiles@otterca.com
 * 
 * @param <T>
 */
@ParametersAreNonnullByDefault
public abstract class GeneralName<T> {
    private T value;
    private final Type type;

    /**
     * General Name content types. We're mostly concerned with IA5String, (LDAP)
     * Name and OctetString.
     * 
     * @author bgiles
     */
    public enum ContentType {
        OtherName, IA5String, ORAddress, Name, EDIPartyName, OctetString, OID
    };

    /**
     * General Name types. We're mostly concerned with EMAIL, DNS, (LDAP)
     * DIRECTORY, URI and IP_ADDRESS.
     * 
     * @author bgiles@otterca.com
     */
    public enum Type {
        OTHER_NAME(0, ContentType.OtherName), EMAIL(1, ContentType.IA5String), DNS(2,
                ContentType.IA5String), X400_ADDRESS(3, ContentType.ORAddress), DIRECTORY(4,
                ContentType.Name), EDI_PARTY_NAME(5, ContentType.EDIPartyName), URI(6,
                ContentType.IA5String), IP_ADDRESS(7, ContentType.OctetString), REGISTERED_ID(8,
                ContentType.OID);

        protected int id;
        protected ContentType contentType;

        private Type(int id, ContentType contentType) {
            this.id = id;
            this.contentType = contentType;
        }

        public int getId() {
            return id;
        }

        public ContentType getContentType() {
            return contentType;
        }
    };

    /**
     * Constructor.
     */
    protected GeneralName(Type type) {
        this.type = type;
    }

    /**
     * Get type.
     */
    public Type getType() {
        return type;
    }

    /**
     * Get value.
     * 
     * @return
     */
    public T get() {
        return value;
    }

    /**
     * Set value.
     * 
     * @param value
     */
    protected void set(T value) {
        this.value = value;
    }

    /**
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        return (value == null) ? 0 : value.hashCode();
    }

    /**
     * @see java.lang.Object#equals(Object)
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if ((this.value == null) || (o == null)) {
            return false;
        }

        if (!(o instanceof GeneralName)) {
            return false;
        }

        GeneralName<?> rhs = (GeneralName<?>) o;

        if (!type.equals(rhs.type)) {
            return false;
        }

        return this.value.equals(rhs.value);
    }

    /**
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return String.valueOf(value);
    }

    /**
     * Email name (RFC822)
     * 
     * @author bgiles@otterca.com
     */
    public static class Email extends GeneralName<String> {
        public Email() {
            super(Type.EMAIL);
        }

        public Email(String value) {
            super(Type.EMAIL);
            set(value);
        }
    }

    /**
     * Directory name (LDAP/X500 name)
     * 
     * @author bgiles@otterca.com
     */
    public static class Directory extends GeneralName<LdapName> {
        public Directory() {
            super(Type.DIRECTORY);
        }

        public Directory(LdapName name) {
            super(Type.DIRECTORY);
            set(name);
        }

        public Directory(String name) throws InvalidNameException {
            super(Type.DIRECTORY);
            set(new LdapName(name));
        }
    }

    /**
     * URI name
     * 
     * @author bgiles@otterca.com
     */
    public static class URI extends GeneralName<java.net.URI> {
        public URI() {
            super(Type.URI);
        }

        public URI(java.net.URI uri) {
            super(Type.URI);
            set(uri);
        }

        public URI(String uri) throws URISyntaxException {
            super(Type.URI);
            set(new java.net.URI(uri));
        }
    }

    /**
     * DNS name
     * 
     * @author bgiles@otterca.com
     */
    public static class DNS extends GeneralName<String> {
        public DNS() {
            super(Type.DNS);
        }

        public DNS(String dns) {
            super(Type.DNS);
            set(dns);
        }
    }

    /**
     * IP Address
     * 
     * @author bgiles@otterca.com
     */
    public static class IpAddress extends GeneralName<InetAddress> {
        public IpAddress() {
            super(Type.IP_ADDRESS);
        }

        public IpAddress(java.net.InetAddress address) {
            super(Type.IP_ADDRESS);
            set(address);
        }

        public IpAddress(String host) throws UnknownHostException {
            super(Type.IP_ADDRESS);
            set(InetAddress.getByName(host));
        }
    }
}
