package com.upgrad.FoodOrderingApp.service.businness.impl;

import com.upgrad.FoodOrderingApp.service.businness.PaymentService;
import com.upgrad.FoodOrderingApp.service.dao.PaymentRepository;
import com.upgrad.FoodOrderingApp.service.entity.PaymentEntity;
import com.upgrad.FoodOrderingApp.service.exception.PaymentMethodNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PaymentServiceImpl implements PaymentService {

    @Autowired
    PaymentRepository paymentRepository;

    public List<PaymentEntity> getAllPaymentMethods() {
        return paymentRepository.findAll();
    }

    public PaymentEntity getPaymentByUUID(String uuid) throws PaymentMethodNotFoundException {
         PaymentEntity payment = paymentRepository.findByUuid(uuid);
         if(null == payment) {
             throw new PaymentMethodNotFoundException("PNF-002", "No payment method found by this id");
         }
         return payment;
    }

}
