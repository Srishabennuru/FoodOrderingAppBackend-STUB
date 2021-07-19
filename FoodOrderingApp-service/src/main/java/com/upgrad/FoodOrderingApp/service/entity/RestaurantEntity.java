package com.upgrad.FoodOrderingApp.service.entity;

import com.fasterxml.jackson.annotation.JsonProperty;

import javax.naming.spi.DirObjectFactory;
import javax.persistence.*;
import java.util.List;

@Entity
@Table(name = "restaurant")
public class RestaurantEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private int id;

    private String uuid;

    @Column(name = "restaurant_name")
    @JsonProperty("restaurant_name")
    private String restaurantName;

    @Column(name = "photo_url")
    @JsonProperty("photo_url")
    private String photoUrl;

    @Column(name = "customer_rating")
    @JsonProperty("customer_rating")
    private Double customerRating;

    @Column(name = "number_of_customers_rated")
    @JsonProperty("number_of_customers_rated")
    private int numberCustomersRated;

    @Column(name = "average_price_for_two")
    @JsonProperty("average_price_for_two")
    private int avgPrice;

    @OneToOne
    private AddressEntity address;

    @ManyToMany
    private List<ItemEntity> items;

    @ManyToMany
    private List<CategoryEntity> categories;


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

    public String getRestaurantName() {
        return restaurantName;
    }

    public void setRestaurantName(String restaurantName) {
        this.restaurantName = restaurantName;
    }

    public String getPhotoUrl() {
        return photoUrl;
    }

    public void setPhotoUrl(String photoUrl) {
        this.photoUrl = photoUrl;
    }

    public Double getCustomerRating() {
        return customerRating;
    }

    public void setCustomerRating(Double customerRating) {
        this.customerRating = customerRating;
    }

    public int getAvgPrice() {
        return avgPrice;
    }

    public void setAvgPrice(int avgPrice) {
        this.avgPrice = avgPrice;
    }

    public AddressEntity getAddress() {
        return address;
    }

    public void setAddress(AddressEntity address) {
        this.address = address;
    }

    public List<ItemEntity> getItems() {
        return items;
    }

    public void setItems(List<ItemEntity> items) {
        this.items = items;
    }

    public int getNumberCustomersRated() {
        return numberCustomersRated;
    }

    public void setNumberCustomersRated(int numberCustomersRated) {
        this.numberCustomersRated = numberCustomersRated;
    }

    public List<CategoryEntity> getCategories() {
        return categories;
    }

    public void setCategories(List<CategoryEntity> categories) {
        this.categories = categories;
    }
}
