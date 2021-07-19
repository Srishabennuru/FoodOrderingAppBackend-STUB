package com.upgrad.FoodOrderingApp.api.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.upgrad.FoodOrderingApp.service.businness.AddressService;
import com.upgrad.FoodOrderingApp.service.businness.CategoryService;
import com.upgrad.FoodOrderingApp.service.businness.CustomerService;
import com.upgrad.FoodOrderingApp.service.constants.Messages;
import com.upgrad.FoodOrderingApp.service.entity.*;
import com.upgrad.FoodOrderingApp.service.exception.AddressNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.AuthorizationFailedException;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import com.upgrad.FoodOrderingApp.service.exception.SaveAddressException;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/category")
public class CategoryController {

    @Autowired
    CategoryService categoryService;


    @GetMapping("/{categoryId}")
    public ResponseEntity<String> getCategoryById(@PathVariable("categoryId") String categoryId) throws Exception {
        try {
            CategoryEntity categoryEntity = categoryService.getCategoryById(categoryId);

            return new ResponseEntity<>(new ObjectMapper().writeValueAsString(categoryEntity), HttpStatus.OK);
        } catch (CategoryNotFoundException ex) {
            JSONObject response = new JSONObject();
            response.put("code", ex.getCode());
            response.put("status", ex.getErrorMessage());
            return new ResponseEntity<>(response.toString(), HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping
    public ResponseEntity<String> getCategories() throws Exception {
        List<CategoryEntity> categories = categoryService.getAllCategoriesOrderedByName();

        return new ResponseEntity<>(new ObjectMapper().writeValueAsString(categories), HttpStatus.OK);
    }


}
