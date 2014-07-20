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

import java.lang.reflect.ParameterizedType;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.persistence.EntityManager;
import javax.persistence.EntityTransaction;
import javax.persistence.PersistenceContext;

/**
 * Implementation of JpaDao.
 * 
 * @author bgiles
 * 
 * @param <K>
 *            database key type
 * @param <E>
 *            entity type
 */
@ParametersAreNonnullByDefault
public abstract class JpaDaoImpl<K, E> implements JpaDao<K, E> {
    protected Class<E> entityClass;

    @PersistenceContext
    protected EntityManager entityManager;

    @SuppressWarnings("unchecked")
    public JpaDaoImpl() {
        ParameterizedType genericSuperclass = (ParameterizedType) getClass().getGenericSuperclass();
        this.entityClass = (Class<E>) genericSuperclass.getActualTypeArguments()[1];
    }

    /**
     * Setter exposed for unit tests.
     */
    void setEntityManager(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    /**
     * @see com.otterca.repository.db.JpaDao#persist(E)
     */
    @Override
    public void persist(E entity) {
        entityManager.persist(entity);
    }

    /**
     * @see com.otterca.repository.db.JpaDao#remove(E)
     */
    @Override
    public void remove(E entity) {
        entityManager.remove(entity);
    }

    /**
     * @see com.otterca.repository.db.JpaDao#merge(E)
     */
    @Override
    public E merge(E entity) {
        return entityManager.merge(entity);
    }

    /**
     * @see com.otterca.repository.db.JpaDao#refresh(E)
     */
    @Override
    public void refresh(E entity) {
        entityManager.refresh(entity);
    }

    /**
     * @see com.otterca.repository.db.JpaDao#findById(K)
     */
    @Override
    public E findById(K id) {
        return entityManager.find(entityClass, id);
    }

    /**
     * @see com.otterca.repository.db.JpaDao#flush(E)
     */
    @Override
    public E flush(E entity) {
        entityManager.flush();
        return entity;
    }

    /**
     * @see com.otterca.repository.db.JpaDao#clear()
     */
    public void clear() {
        entityManager.clear();
    }

    /**
     * 
     * @return
     */
    EntityTransaction getTransaction() {
        return entityManager.getTransaction();
    }

    /*
     * @see com.otterca.repository.db.JpaDao#findAll()
     */
    /*
     * @Override
     * 
     * @SuppressWarnings("unchecked") public List<E> findAll() { Object res =
     * getJpaTemplate().execute(new JpaCallback() {
     * 
     * public Object doInJpa(EntityManager em) throws PersistenceException {
     * Query q = em.createQuery("SELECT h FROM " + entityClass.getName() +
     * " h"); return q.getResultList(); }
     * 
     * });
     * 
     * return (List<E>) res; }
     */

    /*
     * (non-Javadoc)
     * 
     * @see com.otterca.repository.db.JpaDao#removeAll()
     */
    /*
     * @Override
     * 
     * @SuppressWarnings("unchecked") public Integer removeAll() { return
     * (Integer) getJpaTemplate().execute(new JpaCallback() {
     * 
     * public Object doInJpa(EntityManager em) throws PersistenceException {
     * Query q = em.createQuery("DELETE FROM " + entityClass.getName() + " h");
     * return q.executeUpdate(); }
     * 
     * }); }
     */
}