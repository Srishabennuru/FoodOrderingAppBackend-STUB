package com.upgrad.FoodOrderingApp.api.controller;

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

@RestController
@RequestMapping("/order")
public class OrderController {

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
    private ItemService itemService;

    @PostMapping
    public ResponseEntity<Response> saveOrder(@RequestHeader("authorization") String authorization,
                                           @RequestBody(required = false) SaveOrderRequest request) {
        try {
            CustomerEntity customer = customerService.getCustomer(getToken(authorization));

            OrderEntity order = new OrderEntity();
            order.setCoupon(orderService.getCouponByCouponId(request.getCouponId()));
            order.setPayment(paymentService.getPaymentByUUID(request.getPaymentId()));
            order.setAddress(addressService.getAddressByUUID(request.getAddressId(), customer));
            order.setRestaurant(restaurantService.restaurantByUUID(request.getRestaurantId()));

            order = orderService.saveOrder(order);

            OrderItemEntity orderItem = new OrderItemEntity();
            orderItem.setOrder(order);
            orderItem = orderService.saveOrderItem(orderItem);

            return new ResponseEntity<>(new Response(order.getUuid(), null, Messages.ORDER_SUCCESS),
                    HttpStatus.CREATED);
        } catch (AddressNotFoundException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.NOT_FOUND);
        } catch (PaymentMethodNotFoundException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.NOT_FOUND);
        } catch (RestaurantNotFoundException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.NOT_FOUND);
        } catch (CouponNotFoundException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.NOT_FOUND);
        } catch (AuthorizationFailedException ex) {
            return new ResponseEntity<>(new Response(null, ex.getCode(), ex.getErrorMessage()), HttpStatus.FORBIDDEN);
        }
    }

    @GetMapping
    public ResponseEntity<String> getOrders(@RequestHeader("authorization") String authorization) throws Exception {
        try {
            CustomerEntity customer = customerService.getCustomer(getToken(authorization));
            List<OrderEntity> orders = orderService.getOrdersByCustomers(customer.getUuid());

            JSONArray addArray = new JSONArray();
            for(OrderEntity order : orders) {
                addArray.put(order);
            }

            JSONObject response = new JSONObject();
            response.put("orders", addArray);

            return new ResponseEntity<>(response.toString(), HttpStatus.OK);
        } catch (AuthorizationFailedException ex) {
            JSONObject response = new JSONObject();
            response.put("code", ex.getCode());
            response.put("status", ex.getErrorMessage());
            return new ResponseEntity<>(response.toString(), HttpStatus.FORBIDDEN);
        }
    }

    @GetMapping("/coupon/{couponName}")
    public ResponseEntity<String> getCoupon(@RequestHeader("authorization") String authorization,
                                              @PathVariable("couponName") String couponName) throws Exception {
        try {
            CustomerEntity customer = customerService.getCustomer(getToken(authorization));
            CouponEntity coupon = orderService.getCouponByCouponName(couponName);

            JSONObject response = new JSONObject();
            response.put("id", coupon.getUuid());
            response.put("coupon_name", coupon.getCouponName());

            return new ResponseEntity<>(response.toString(), HttpStatus.OK);
        } catch (AuthorizationFailedException ex) {
            JSONObject response = new JSONObject();
            response.put("code", ex.getCode());
            response.put("status", ex.getErrorMessage());
            return new ResponseEntity<>(response.toString(), HttpStatus.FORBIDDEN);
        } catch (CouponNotFoundException ex) {
            JSONObject response = new JSONObject();
            response.put("code", ex.getCode());
            response.put("status", ex.getErrorMessage());
            return new ResponseEntity<>(response.toString(), HttpStatus.NOT_FOUND);
        }

    }

    private String getToken(String authorization) {
        return authorization.substring("Bearer ".length()).trim();
    }

}
