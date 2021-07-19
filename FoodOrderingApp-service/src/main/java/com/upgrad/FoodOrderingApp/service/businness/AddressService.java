package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.dao.AddressRepository;
import com.upgrad.FoodOrderingApp.service.dao.StateRepository;
import com.upgrad.FoodOrderingApp.service.entity.AddressEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.entity.StateEntity;
import com.upgrad.FoodOrderingApp.service.exception.AddressNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SaveAddressException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

public interface AddressService {

    StateEntity getStateByUUID(String uuid) throws AddressNotFoundException;

    AddressEntity getAddressByUUID(String uuid, CustomerEntity customerEntity) throws AddressNotFoundException, AuthorizationFailedException;

    AddressEntity deleteAddress(AddressEntity addressEntity);

    List<AddressEntity> getAllAddress(CustomerEntity customerEntity);

    List<StateEntity> getAllStates();

    AddressEntity saveAddress(AddressEntity address, StateEntity state) throws SaveAddressException;

}

