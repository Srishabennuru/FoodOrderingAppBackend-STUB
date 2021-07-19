package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.entity.CouponEntity;
import com.upgrad.FoodOrderingApp.service.entity.OrderEntity;
import com.upgrad.FoodOrderingApp.service.entity.OrderItemEntity;
import com.upgrad.FoodOrderingApp.service.exception.CouponNotFoundException;

import java.util.List;

public interface OrderService {

    CouponEntity getCouponByCouponId(String uuid) throws CouponNotFoundException;

    OrderEntity saveOrder(OrderEntity order);

    OrderItemEntity saveOrderItem(OrderItemEntity orderItem);

    List<OrderEntity> getOrdersByCustomers(String customerId);

    CouponEntity getCouponByCouponName(String couponName) throws CouponNotFoundException;
}
