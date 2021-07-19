package com.upgrad.FoodOrderingApp.service.businness.impl;

import com.upgrad.FoodOrderingApp.service.businness.CategoryService;
import com.upgrad.FoodOrderingApp.service.dao.CategoryRepository;
import com.upgrad.FoodOrderingApp.service.entity.CategoryEntity;
import com.upgrad.FoodOrderingApp.service.exception.CategoryNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

@Service
public class CategoryServiceImpl implements CategoryService {

    @Autowired
    CategoryRepository categoryRepository;

    public List<CategoryEntity> getCategoriesByRestaurant(String restaurantId) {
        List<CategoryEntity> categories = categoryRepository.findAll();
        List<CategoryEntity> result = new ArrayList<>();
        for(CategoryEntity category : categories) {
            if(category.getRestaurants().stream().anyMatch(res -> res.getUuid().equals(restaurantId))) {
                result.add(category);
            }
        }
        return result;
    }

    public CategoryEntity getCategoryById(String categoryId) throws CategoryNotFoundException {
        if(StringUtils.isEmpty(categoryId)) {
            throw new CategoryNotFoundException("CNF-001", "Category id field should not be empty");
        }
        CategoryEntity categoryEntity =  categoryRepository.findByUuid(categoryId);
        if(null == categoryEntity) {
            throw new CategoryNotFoundException("CNF-002", "No category by this id");
        }
        return categoryEntity;
    }

    public List<CategoryEntity> getAllCategoriesOrderedByName() {
        return categoryRepository.findAll();
    }

}
