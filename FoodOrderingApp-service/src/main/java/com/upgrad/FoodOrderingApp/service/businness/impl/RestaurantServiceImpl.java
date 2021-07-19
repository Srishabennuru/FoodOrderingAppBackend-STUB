package com.upgrad.FoodOrderingApp.service.businness.impl;

import com.upgrad.FoodOrderingApp.service.businness.RestaurantService;
import com.upgrad.FoodOrderingApp.service.dao.RestaurantRepository;
import com.upgrad.FoodOrderingApp.service.entity.RestaurantEntity;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.RestaurantNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class RestaurantServiceImpl implements RestaurantService {

    @Autowired
    RestaurantRepository restaurantRepository;

    public RestaurantEntity restaurantByUUID(String restaurantId) throws RestaurantNotFoundException {

        if(StringUtils.isEmpty(restaurantId)) {
            throw new RestaurantNotFoundException("RNF-002", "Restaurant id field should not be empty");
        }
        RestaurantEntity restaurant = restaurantRepository.findByUuid(restaurantId);
        if(null == restaurant) {
            throw new RestaurantNotFoundException("RNF-001", "No restaurant by this id");
        }
        return restaurant;
    }

    public List<RestaurantEntity> restaurantsByName(String restaurantName) throws RestaurantNotFoundException {
        if(StringUtils.isEmpty(restaurantName)) {
            throw new RestaurantNotFoundException("RNF-003", "Restaurant name field should not be empty");
        }
        return restaurantRepository.findAllByRestaurantName(restaurantName);
    }

    public List<RestaurantEntity> restaurantByCategory(String categoryId) throws CategoryNotFoundException {
        if(StringUtils.isEmpty(categoryId)) {
            throw new CategoryNotFoundException("CNF-001", "Category id field should not be empty");
        }
        List<RestaurantEntity> restaurants = restaurantRepository.findAll();
        List<RestaurantEntity> result = new ArrayList<>();
        for(RestaurantEntity res : restaurants) {
            if(res.getCategories().stream().anyMatch(cat -> cat.getUuid().equals(categoryId))) {
                result.add(res);
            }
        }

        if(CollectionUtils.isEmpty(result)) {
            throw new CategoryNotFoundException("CNF-002", "No category by this id");
        }
        return result;
    }

    public List<RestaurantEntity> restaurantsByRating() {
        return null;
    }

}
