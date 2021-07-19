package com.upgrad.FoodOrderingApp.service.businness.impl;

import com.upgrad.FoodOrderingApp.service.businness.AddressService;
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
import org.springframework.util.StringUtils;

import java.util.List;

@Service
public class AddressServiceImpl implements AddressService {

    @Autowired
    AddressRepository addressRepository;

    @Autowired
    StateRepository stateRepository;

    public StateEntity getStateByUUID(String uuid) throws AddressNotFoundException {
        StateEntity state = stateRepository.findByUuid(uuid);
        if(null == state) {
            throw new AddressNotFoundException("ANF-002", "No state by this state id");
        }
        return state;
    }

    public AddressEntity getAddressByUUID(String uuid, CustomerEntity customer) throws AddressNotFoundException, AuthorizationFailedException {
        AddressEntity address =  addressRepository.findByUuid(uuid);
        if(null == address) {
            throw new AddressNotFoundException("ANF-003", "No address by this id");
        }

        if(!customer.getAddressEntities().stream().anyMatch(ae -> ae.getUuid().equals(uuid))) {
            throw new AuthorizationFailedException("ATHR-004", "You are not authorized to view/update/delete any one else's address");
        }

        return address;
    }

    public AddressEntity deleteAddress(AddressEntity addressEntity) {
        addressRepository.delete(addressEntity);
        return addressEntity;
    }

    public List<AddressEntity> getAllAddress(CustomerEntity customerEntity) {
        return null;// addressRepository.findAllById(customerEntity.getAddressEntities().stream().map(ae -> ae.getId()).collect(Collectors.toList()));
    }

    public List<StateEntity> getAllStates() {
        return stateRepository.findAll();
    }

    public AddressEntity saveAddress(AddressEntity address, StateEntity state) throws SaveAddressException{

        if(StringUtils.isEmpty(address.getCity())) {
            throw new SaveAddressException("SAR-001", "No field can be empty");
        }
        if(StringUtils.isEmpty(address.getCity()) || StringUtils.isEmpty(address.getPincode())) {
            throw new SaveAddressException("SAR-002", "Invalid pincode");
        }

        address.setState(state);
        return addressRepository.save(address);
    }
}

