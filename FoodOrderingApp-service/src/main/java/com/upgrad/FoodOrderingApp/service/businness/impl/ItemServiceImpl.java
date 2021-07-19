package com.upgrad.FoodOrderingApp.service.businness.impl;

import com.upgrad.FoodOrderingApp.service.businness.ItemService;
import com.upgrad.FoodOrderingApp.service.dao.ItemRepository;
import com.upgrad.FoodOrderingApp.service.dao.OrderItemRepository;
import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
import com.upgrad.FoodOrderingApp.service.entity.ItemEntity;
import com.upgrad.FoodOrderingApp.service.entity.RestaurantEntity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ItemServiceImpl implements ItemService {

    @Autowired
    ItemRepository itemRepository;

    public List<ItemEntity> getItemsByPopularity(RestaurantEntity restaurantEntity) {
        return restaurantEntity.getItems();
    }

    public List<ItemEntity> getItemsByCategoryAndRestaurant(String restaurantId, String categoryId) {
        List<ItemEntity> items = itemRepository.findAll();

        List<ItemEntity> result = new ArrayList<>();
        for(ItemEntity item : items) {
            if(item.getRestaurants().stream().anyMatch(res -> res.getUuid().equals(restaurantId))) {
                result.add(item);
            }
        }
        for(ItemEntity item : items) {
            if(item.getCategories().stream().anyMatch(cat -> cat.getUuid().equals(categoryId))) {
                result.add(item);
            }
        }
        return result;
    }
}
