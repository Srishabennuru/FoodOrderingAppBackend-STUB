package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import com.upgrad.FoodOrderingApp.service.exception.UpdateCustomerException;

public interface CustomerService {

    CustomerEntity getCustomer(String accessToken) throws AuthorizationFailedException;

    CustomerEntity saveCustomer(CustomerEntity customer) throws SignUpRestrictedException;

    CustomerAuthEntity authenticate(String contact, String password) throws AuthenticationFailedException;

    CustomerEntity updateCustomer(CustomerEntity customer) throws AuthorizationFailedException;

    CustomerAuthEntity logout(String accessToken) throws AuthorizationFailedException;

    CustomerEntity updateCustomerPassword(String oldPwd, String newPwd, CustomerEntity customerEntity) throws UpdateCustomerException;
}
