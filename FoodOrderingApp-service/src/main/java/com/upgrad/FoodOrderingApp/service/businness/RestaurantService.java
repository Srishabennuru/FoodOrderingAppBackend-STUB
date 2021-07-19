package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.entity.RestaurantEntity;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.RestaurantNotFoundException;

import java.util.List;

public interface RestaurantService {

    RestaurantEntity restaurantByUUID(String restaurantId) throws RestaurantNotFoundException;

    List<RestaurantEntity> restaurantsByName(String restaurantName) throws RestaurantNotFoundException ;

    List<RestaurantEntity> restaurantByCategory(String categoryId) throws CategoryNotFoundException;

    List<RestaurantEntity> restaurantsByRating();
}
