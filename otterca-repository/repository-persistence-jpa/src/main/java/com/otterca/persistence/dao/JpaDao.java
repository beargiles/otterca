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
package com.otterca.persistence.dao;

import javax.annotation.ParametersAreNonnullByDefault;

/**
 * Abstraction of JPA DataAccessObjects (DAOs).
 * 
 * Implementation Note: this interface assumes a JPA backend. It may be
 * substantially rewritten if we switch to a NoSQL backend.
 * 
 * @author bgiles@otterca.com
 * 
 * @param <K>
 *            database key type
 * @param <E>
 *            entity type
 */
@ParametersAreNonnullByDefault
public interface JpaDao<K, E> {

    /**
     * Persist the entity.
     * 
     * @param entity
     */
    void persist(E entity);

    /**
     * Remove the entity.
     * 
     * @param entity
     */
    void remove(E entity);

    /**
     * Merge the entity.
     * 
     * @param entity
     * @return
     */
    E merge(E entity);

    /**
     * Refresh the entity.
     * 
     * @param entity
     */
    void refresh(E entity);

    /**
     * Find the entity by primary key.
     * 
     * @param id
     * @return
     */
    E findById(K id);

    /**
     * Flush the entity to the database.
     * 
     * @param entity
     * @return
     */
    E flush(E entity);

    // List<E> findAll();

    // Integer removeAll();
}