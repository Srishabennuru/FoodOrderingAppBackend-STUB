package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.service.businness.AddressService;
import com.upgrad.FoodOrderingApp.service.businness.CustomerService;
import com.upgrad.FoodOrderingApp.service.constants.Messages;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.AddressNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SaveAddressException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class AddressController {

    @Autowired
    AddressService addressService;

    @Autowired
    CustomerService customerService;

    @PostMapping("/address")
    public ResponseEntity<Response> saveAddress(@RequestHeader("authorization") String authorization,
                                                @RequestBody(required = false) AddressEntity address) {
        try {

            CustomerEntity customer = customerService.getCustomer(getToken(authorization));
            StateEntity state = addressService.getStateByUUID(address.getStateUuid());

            address = addressService.saveAddress(address, state);
            return new ResponseEntity<>(new Response(address.getUuid(), null, Messages.ADD_UPDATE_SUCCESS),
                    HttpStatus.CREATED);
        } catch (AddressNotFoundException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.NOT_FOUND);
        } catch (AuthorizationFailedException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.FORBIDDEN);
        } catch (SaveAddressException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.BAD_REQUEST);
        }
    }

    @DeleteMapping("/address/{uuid}")
    public ResponseEntity<Response> deleteAddress(@RequestHeader("authorization") String authorization,
                                                  @PathVariable("uuid") String uuid,
                                                  @RequestBody(required = false) AddressEntity request) {
        try {

            CustomerEntity customer = customerService.getCustomer(getToken(authorization));

            AddressEntity address = addressService.getAddressByUUID(uuid, customer);
            address = addressService.deleteAddress(address);

            return new ResponseEntity<>(new Response(address.getUuid(), null, Messages.ADD_DELETE_SUCCESS),
                    HttpStatus.OK);
        } catch (AddressNotFoundException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.NOT_FOUND);
        } catch (AuthorizationFailedException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.FORBIDDEN);
        }
    }

    @GetMapping("/address/customer")
    public ResponseEntity<String> getAddress(@RequestHeader("authorization") String authorization) throws Exception {
        try {

            CustomerEntity customer = customerService.getCustomer(getToken(authorization));
            List<AddressEntity> addresses = addressService.getAllAddress(customer);

            JSONArray addArray = new JSONArray();
            for(AddressEntity address : addresses) {
                addArray.put(address);
            }

            JSONObject response = new JSONObject();
            response.put("addresses", addArray);

            return new ResponseEntity<>(response.toString(), HttpStatus.OK);
        } catch (AuthorizationFailedException ex) {
            JSONObject response = new JSONObject();
            response.put("code", ex.getCode());
            response.put("status", ex.getErrorMessage());
            return new ResponseEntity<>(response.toString(), HttpStatus.FORBIDDEN);
        }
    }

    @GetMapping("/states")
    public ResponseEntity<String> getStates() throws Exception {
        List<StateEntity> states = addressService.getAllStates();
        JSONObject response = new JSONObject();
        response.put("states", states);
        return new ResponseEntity<>(response.toString(), HttpStatus.OK);
    }


    private String getToken(String authorization) {
        return authorization.substring("Bearer ".length()).trim();
    }
}
