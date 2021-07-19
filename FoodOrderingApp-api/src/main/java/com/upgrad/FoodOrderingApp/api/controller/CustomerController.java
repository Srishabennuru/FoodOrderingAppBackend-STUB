package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.service.businness.CustomerService;
import com.upgrad.FoodOrderingApp.service.constants.Messages;
import com.upgrad.FoodOrderingApp.service.entity.CustomerAuthEntity;
import com.upgrad.FoodOrderingApp.service.entity.CustomerEntity;
import com.upgrad.FoodOrderingApp.service.entity.Password;
import com.upgrad.FoodOrderingApp.service.entity.Response;
import com.upgrad.FoodOrderingApp.service.exception.AuthenticationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.SignUpRestrictedException;
import com.upgrad.FoodOrderingApp.service.exception.UpdateCustomerException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;

import static java.util.Base64.getDecoder;

@RestController
@RequestMapping("/customer")
public class CustomerController {

    @Autowired
    CustomerService customerService;

    @PostMapping("/signup")
    public ResponseEntity<Response> signup(@RequestBody CustomerEntity customerEntity) {
        try {
            if(StringUtils.isEmpty(customerEntity.getEmailAddress())) {
                throw new SignUpRestrictedException(Messages.SGR_005, Messages.MISSING_EMAIL);
            }
            CustomerEntity createdCustomer = customerService.saveCustomer(customerEntity);
            return new ResponseEntity<Response>(new Response(createdCustomer.getUuid(), null, Messages.SIGNUP_SUCCESS),
            HttpStatus.CREATED);
        } catch(SignUpRestrictedException sre) {
            return ResponseEntity.badRequest().body(new Response(null, sre.getCode(), sre.getErrorMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Response> login(@RequestHeader("authorization") String authorization) {
        try {
            String[] values = getCustomerAuthCreds(authorization);

            if(StringUtils.isEmpty(values[0]) || StringUtils.isEmpty(values[1])) {
                throw new AuthenticationFailedException(Messages.ATH_003, "");
            }

            CustomerAuthEntity createdCustomerAuth = customerService.authenticate(values[0], values[1]);
            HttpHeaders headers = new HttpHeaders();
            headers.set("access-token", createdCustomerAuth.getAccessToken());

            return new ResponseEntity<Response>(new Response(createdCustomerAuth.getCustomer().getUuid(), null, Messages.USR_SIGNIN_SUCCESS),
                    headers, HttpStatus.OK);
        } catch(AuthenticationFailedException ex) {
            return new ResponseEntity<Response>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Response> logout(@RequestHeader("authorization") String authorization) {
        try {
            CustomerAuthEntity createdCustomerAuth = customerService.logout(getToken(authorization));

            return new ResponseEntity<Response>(new Response(createdCustomerAuth.getCustomer().getUuid(), null, Messages.USR_SIGNIN_SUCCESS),
                    HttpStatus.OK);
        } catch(AuthorizationFailedException ex) {
            return new ResponseEntity<Response>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.FORBIDDEN);
        }
    }

    private String getToken(String authorization) {
        return authorization.substring("Bearer ".length()).trim();
    }

    private String[] getCustomerAuthCreds(String authorization) {
        String base64Credentials = authorization.substring("Basic".length()).trim();
        byte[] credDecoded = getDecoder().decode(base64Credentials);
        String credentials = new String(credDecoded, StandardCharsets.UTF_8);
        // credentials = username:password
        return credentials.split(":", 2);
    }

    @PutMapping
    public ResponseEntity<Response> updateCustomer(@RequestHeader("authorization") String authorization,
                                                   @RequestBody CustomerEntity request) {
        try {
            if(StringUtils.isEmpty(request.getFirstName())) {
                return new ResponseEntity<>(new Response(null, Messages.UCR_002, ""), HttpStatus.BAD_REQUEST);
            }

            String token = getToken(authorization);
            /*if(StringUtils.isEmpty(token)) {
                return new ResponseEntity<>(new Response(null, Messages.UCR_002, ""), HttpStatus.BAD_REQUEST);
            }*/
            CustomerEntity customer = customerService.getCustomer(token);
            customer.setFirstName(request.getFirstName());
            customer.setLastName(request.getLastName());
            CustomerEntity updated = customerService.updateCustomer(customer);
            return new ResponseEntity<>(new Response(updated.getUuid(), null, Messages.SIGNUP_SUCCESS),
                    HttpStatus.OK);
        } catch(AuthorizationFailedException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.FORBIDDEN);
        }
    }

    @PutMapping("/password")
    public ResponseEntity<Response> updatePassword(@RequestHeader("authorization") String authorization,
                                                   @RequestBody Password request) {
        try {

            if(StringUtils.isEmpty(request.getOldPassword()) || StringUtils.isEmpty(request.getNewPassword())) {
                return new ResponseEntity<>(new Response(null, Messages.UCR_003, ""), HttpStatus.BAD_REQUEST);
            }

            String token = getToken(authorization);
            CustomerEntity customer = customerService.getCustomer(token);

            CustomerEntity updated = customerService.updateCustomerPassword(request.getOldPassword(), request.getNewPassword(), customer);
            return new ResponseEntity<>(new Response(updated.getUuid(), null, Messages.SIGNUP_SUCCESS),
                    HttpStatus.OK);
        } catch(UpdateCustomerException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.BAD_REQUEST);
        } catch(AuthorizationFailedException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.FORBIDDEN);
        }
    }


}
