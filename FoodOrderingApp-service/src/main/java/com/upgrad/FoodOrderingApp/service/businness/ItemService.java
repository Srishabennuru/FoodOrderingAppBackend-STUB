package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.entity.ItemEntity;
import com.upgrad.FoodOrderingApp.service.entity.RestaurantEntity;

import java.util.List;

public interface ItemService {

    List<ItemEntity> getItemsByPopularity(RestaurantEntity restaurantEntity);

    List<ItemEntity> getItemsByCategoryAndRestaurant(String restaurantId, String categoryId);
}
