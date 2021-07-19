package com.upgrad.FoodOrderingApp.service.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreType;

import java.util.List;

public class Response {


    private String id;
    private String code;
    private String status;
    private List<AddressEntity> addresses;
    private List<StateEntity> states;

    public Response() {
    }

    public Response(String uuid, String code, String status) {
        this.id = uuid;
        this.code = code;
        this.status = status;
    }

    public Response(List<AddressEntity> addresses, List<StateEntity> states) {
        this.addresses = addresses;
        this.states = states;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public List<AddressEntity> getAddresses() {
        return addresses;
    }

    public void setAddresses(List<AddressEntity> addresses) {
        this.addresses = addresses;
    }

    public List<StateEntity> getStates() {
        return states;
    }

    public void setStates(List<StateEntity> states) {
        this.states = states;
    }
}
