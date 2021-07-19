package com.upgrad.FoodOrderingApp.service;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.orm.hibernate5.LocalSessionFactoryBean;

/**
 * Enabling the component scan and entity scan of classes in the below mentioned "com.upgrad.FoodOrderingApp.service" and "com.upgrad.FoodOrderingApp.service.entity" packages respectively.
 */
@Configuration
@ComponentScan("com.upgrad.FoodOrderingApp.service")
@EnableJpaRepositories(basePackages = "com.upgrad.FoodOrderingApp.service.dao")
@EntityScan("com.upgrad.FoodOrderingApp.service.entity")
public class ServiceConfiguration {

   /* @Bean(name="entityManagerFactory")
    public LocalSessionFactoryBean sessionFactory() {
        LocalSessionFactoryBean sessionFactory = new LocalSessionFactoryBean();

        return sessionFactory;
    }*/

}
