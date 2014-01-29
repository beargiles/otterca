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

import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;

import javax.annotation.ParametersAreNonnullByDefault;
import javax.sql.DataSource;

import org.apache.commons.dbcp.BasicDataSource;
import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalEntityManagerFactoryBean;

/**
 * Configuration used in DAO tests. All singleton beans use lazy initialization.
 * 
 * @author bgiles@otterca.com
 */
@Configuration
@Profile("dev")
@ParametersAreNonnullByDefault
public class H2Configuration {
    private static final ResourceBundle bundle = ResourceBundle.getBundle(H2Configuration.class
            .getName());
    private static final ResourceBundle masterkey = ResourceBundle.getBundle("masterkey");
    private volatile DataSource dataSource;
    private volatile LocalEntityManagerFactoryBean factory;
    private volatile JpaTransactionManager txMgr;
    private Map<String, String> JpaPropertyMap = new HashMap<String, String>();

    public H2Configuration() {
        JpaPropertyMap.put("javax.persistence.jdbc.driver", bundle.getString("driverClassName"));
        JpaPropertyMap.put("javax.persistence.url", bundle.getString("url"));
        JpaPropertyMap.put("javax.persistence.username", bundle.getString("username"));
        JpaPropertyMap.put("javax.persistence.password", bundle.getString("password"));

        JpaPropertyMap
                .put("hibernate.connection.driver_class", bundle.getString("driverClassName"));
        JpaPropertyMap.put("hibernate.connection.url", bundle.getString("url"));
        JpaPropertyMap.put("hibernate.connection.username", bundle.getString("username"));
        JpaPropertyMap.put("hibernate.connection.password", bundle.getString("password"));
        JpaPropertyMap.put("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
        JpaPropertyMap.put("hibernate.hbm2ddl.auto", bundle.getString("hibernate.hbm2ddl.auto"));
        JpaPropertyMap.put("hibernate.show_sql", bundle.getString("hibernate.show_sql"));
    }

    /**
     * Get dataSource for H2 database.
     * 
     * @return
     */
    @Bean
    public DataSource getDataSource() {
        if (dataSource == null) {
            synchronized (this) {
                if (dataSource == null) {
                    BasicDataSource ds = new BasicDataSource();
                    ds.setDriverClassName(bundle.getString("driverClassName"));
                    ds.setUrl(bundle.getString("url"));
                    ds.setUsername(bundle.getString("username"));
                    BasicTextEncryptor encryptor = new BasicTextEncryptor();
                    encryptor.setPassword(masterkey.getString("master.password"));
                    ds.setPassword(encryptor.decrypt(bundle.getString("password")));
                    ds.setValidationQuery(bundle.getString("validationQuery"));
                    dataSource = ds;
                }
            }
        }
        return dataSource;
    }

    /**
     * Get entity manager for PostgreSQL database.
     * 
     * @return
     */
    @Bean
    public LocalEntityManagerFactoryBean getEntityManagerFactory() {
        if (factory == null) {
            synchronized (this) {
                if (factory == null) {
                    factory = new LocalEntityManagerFactoryBean();
                    factory.setPersistenceUnitName(bundle.getString("persistenceUnitName"));
                    factory.setJpaPropertyMap(JpaPropertyMap);
                }
            }
        }
        return factory;
    }

    /**
     * Get transaction manager for this entity manager factory.
     * 
     * @return
     */
    @Bean
    public JpaTransactionManager getTransactionManager() {
        if (txMgr == null) {
            synchronized (this) {
                if (txMgr == null) {
                    txMgr = new JpaTransactionManager(getEntityManagerFactory().getObject());
                }
            }
        }
        return txMgr;
    }

    /**
     * Get Certificate DAO
     * 
     * @return
     */
    @Bean
    public X509CertificateDao getX509CertificateDao() {
        X509CertificateDaoJpa dao = new X509CertificateDaoJpa();
        dao.setEntityManager(getEntityManagerFactory().getObject().createEntityManager());
        return dao;
    }
}