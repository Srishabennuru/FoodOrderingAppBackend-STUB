package com.upgrad.FoodOrderingApp.service.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "address")
public class AddressEntity {

    public AddressEntity() {

    }

    public AddressEntity(String uuid, String flatBuilNo, String locality, String city, String pincode, StateEntity state) {
        this.uuid = uuid;
        this.flatBuilNo = flatBuilNo;
        this.locality = locality;
        this.city = city;
        this.pincode = pincode;
        this.state = state;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private int id;

    private String uuid;

    @Column(name = "flat_buil_number")
    @JsonProperty("flat_building_name")
    private String flatBuilNo;

    private String locality;

    private String city;

    private String pincode;

    @ManyToOne
    private StateEntity state;

    @JsonProperty("state_uuid")
    private String stateUuid;

    private int active;

    @ManyToMany
    private List<CustomerEntity> customerEntities;

    public List<CustomerEntity> getCustomerEntities() {
        return customerEntities;
    }

    public void setCustomerEntities(List<CustomerEntity> customerEntities) {
        this.customerEntities = customerEntities;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getFlatBuilNo() {
        return flatBuilNo;
    }

    @JsonProperty("flat_building_name")
    public void setFlatBuilNo(String flatBuilNo) {
        this.flatBuilNo = flatBuilNo;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getPincode() {
        return pincode;
    }

    public void setPincode(String pincode) {
        this.pincode = pincode;
    }

    public StateEntity getState() {
        return state;
    }

    public void setState(StateEntity state) {
        this.state = state;
    }

    public int getActive() {
        return active;
    }

    public void setActive(int active) {
        this.active = active;
    }

    public String getStateUuid() {
        return stateUuid;
    }

    @JsonProperty("state_uuid")
    public void setStateUuid(String stateUuid) {
        this.stateUuid = stateUuid;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");

        sb.append("id: ").append(toIndentedString(id)).append("\n");
        sb.append("flatBuildingName: ").append(toIndentedString(flatBuilNo)).append("\n");
        sb.append("locality: ").append(toIndentedString(locality)).append("\n");
        sb.append("city: ").append(toIndentedString(city)).append("\n");
        sb.append("pincode: ").append(toIndentedString(pincode)).append("\n");
        sb.append("state: ").append(toIndentedString(state)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Convert the given object to string with each line indented by 4 spaces
     * (except the first line).
     */
    private String toIndentedString(java.lang.Object o) {
        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n    ");
    }
}
