package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;

import java.util.List;

public interface CategoryService {

    List<CategoryEntity> getCategoriesByRestaurant(String restaurantId);

    CategoryEntity getCategoryById(String categoryId) throws CategoryNotFoundException;

    List<CategoryEntity> getAllCategoriesOrderedByName();
}
