package com.upgrad.FoodOrderingApp.service.businness.impl;

import com.upgrad.FoodOrderingApp.service.businness.OrderService;
import com.upgrad.FoodOrderingApp.service.dao.CouponRepository;
import com.upgrad.FoodOrderingApp.service.dao.OrderItemRepository;
import com.upgrad.FoodOrderingApp.service.dao.OrderRepository;
import com.upgrad.FoodOrderingApp.service.entity.CouponEntity;
import com.upgrad.FoodOrderingApp.service.entity.OrderEntity;
import com.upgrad.FoodOrderingApp.service.entity.OrderItemEntity;
import com.upgrad.FoodOrderingApp.service.exception.CouponNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class OrderServiceImpl implements OrderService {

    @Autowired
    CouponRepository couponRepository;

    @Autowired
    OrderRepository orderRepository;

    @Autowired
    OrderItemRepository orderItemRepository;

    public CouponEntity getCouponByCouponId(String uuid) throws CouponNotFoundException {
        CouponEntity coupon = couponRepository.findByUuid(uuid);
        if(null == coupon) {
            throw new CouponNotFoundException("CPF-002", "No coupon by this id");
        }
        return coupon;
    }

    public OrderEntity saveOrder(OrderEntity order) {
        return orderRepository.save(order);
    }

    public OrderItemEntity saveOrderItem(OrderItemEntity orderItem) {
        return orderItemRepository.save(orderItem);
    }

    public List<OrderEntity> getOrdersByCustomers(String customerId) {
        List<OrderEntity> orders = orderRepository.findAll();
        return orders.stream().filter(o -> o.getCustomer().getUuid().equals(customerId))
                .collect(Collectors.toList());
    }

    public CouponEntity getCouponByCouponName(String couponName) throws CouponNotFoundException {
        if(StringUtils.isEmpty(couponName)) {
            throw new CouponNotFoundException("CPF-002", "Coupon name field should not be empty");
        }
        CouponEntity coupon = couponRepository.findByCouponName(couponName);
        if(null == coupon) {
            throw new CouponNotFoundException("CPF-001", "No coupon by this name");
        }
        return coupon;
    }
}
