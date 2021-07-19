package com.upgrad.FoodOrderingApp.api.controller;

import com.upgrad.FoodOrderingApp.service.businness.ItemService;
import com.upgrad.FoodOrderingApp.service.businness.RestaurantService;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.RestaurantNotFoundException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/item")
public class ItemController {

    @Autowired
    ItemService itemService;

    @Autowired
    RestaurantService restaurantService;

    @GetMapping("/restaurant/{restaurantId}")
    public ResponseEntity<String> getItemRestaurant(@PathVariable("restaurantId") String restaurantId) throws Exception {
        try {
            RestaurantEntity restaurant = restaurantService.restaurantByUUID(restaurantId);
            List<ItemEntity> items = itemService.getItemsByPopularity(restaurant);

            JSONArray addArray = new JSONArray();
            for(ItemEntity itemEntity : items) {
                addArray.put(itemEntity);
            }
//
//            JSONObject response = new JSONObject();
//            response.put("items", addArray);

            return new ResponseEntity<>(addArray.toString(), HttpStatus.OK);
        } catch(RestaurantNotFoundException ex) {
            JSONObject response = new JSONObject();
            response.put("code", ex.getCode());
            response.put("status", ex.getErrorMessage());
            return new ResponseEntity<>(response.toString(), HttpStatus.NOT_FOUND);
        }




    }
}
