package com.upgrad.FoodOrderingApp.api.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.upgrad.FoodOrderingApp.service.businness.*;
import com.upgrad.FoodOrderingApp.service.constants.Messages;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@RestController
@RequestMapping("/restaurant")
public class RestaurantController {

    @Autowired
    private OrderService orderService;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private PaymentService paymentService;

    @Autowired
    private AddressService addressService;

    @Autowired
    private RestaurantService restaurantService;

    @Autowired
    private CategoryService categoryService;

    @Autowired
    private ItemService itemService;

    @GetMapping("/{restaurantId}")
    public ResponseEntity<String> getRestaurantById(@PathVariable("restaurantId") String restaurantId) throws Exception {
        try {
            RestaurantEntity res = restaurantService.restaurantByUUID(restaurantId);
            List<CategoryEntity> categories = categoryService.getCategoriesByRestaurant(restaurantId);
            List<ItemEntity> items = itemService.getItemsByCategoryAndRestaurant(restaurantId, categories.get(0).getUuid());

            JSONObject response = new JSONObject();
            response.put("id", res.getUuid());
            response.put("restaurant_name", res.getRestaurantName());
            response.put("customer_rating", res.getCustomerRating());
            response.put("number_customers_rated", res.getNumberCustomersRated());

            return new ResponseEntity<>(response.toString(), HttpStatus.OK);
        } catch (RestaurantNotFoundException ex) {
            JSONObject response = new JSONObject();
            response.put("code", ex.getCode());
            response.put("status", ex.getErrorMessage());
            return new ResponseEntity<>(response.toString(), HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/name/{restaurantName}")
    public ResponseEntity<String> getRestaurantByName(@PathVariable("restaurantName") String restaurantName) throws Exception {
        try {
            List<RestaurantEntity> res = restaurantService.restaurantsByName(restaurantName);
            List<CategoryEntity> categories = categoryService.getCategoriesByRestaurant(res.get(0).getUuid());
            return new ResponseEntity<>(new ObjectMapper().writeValueAsString(res), HttpStatus.OK);

        } catch (RestaurantNotFoundException ex) {
            JSONObject response = new JSONObject();
            response.put("code", ex.getCode());
            response.put("status", ex.getErrorMessage());
            return new ResponseEntity<>(response.toString(), HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/category/{categoryId}")
    public ResponseEntity<String> getRestaurantByCategory(@PathVariable("categoryId") String categoryId) throws Exception {
        try {
            List<RestaurantEntity> res = restaurantService.restaurantByCategory(categoryId);
            List<CategoryEntity> categories = categoryService.getCategoriesByRestaurant(res.get(0).getUuid());
            return new ResponseEntity<>(new ObjectMapper().writeValueAsString(res), HttpStatus.OK);

        } catch (CategoryNotFoundException ex) {
            JSONObject response = new JSONObject();
            response.put("code", ex.getCode());
            response.put("status", ex.getErrorMessage());
            return new ResponseEntity<>(response.toString(), HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping
    public ResponseEntity<String> getRestaurantsByRating() throws Exception {
        List<RestaurantEntity> res = restaurantService.restaurantsByRating();
        List<CategoryEntity> categories = categoryService.getCategoriesByRestaurant(res.get(0).getUuid());
        return new ResponseEntity<>(new ObjectMapper().writeValueAsString(res), HttpStatus.OK);
    }

}
