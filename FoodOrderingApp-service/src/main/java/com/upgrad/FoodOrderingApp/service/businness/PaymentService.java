package com.upgrad.FoodOrderingApp.service.businness;

import com.upgrad.FoodOrderingApp.service.entity.PaymentEntity;
import com.upgrad.FoodOrderingApp.service.exception.PaymentMethodNotFoundException;

import java.util.List;

public interface PaymentService {

    List<PaymentEntity> getAllPaymentMethods();

    PaymentEntity getPaymentByUUID(String uuid) throws PaymentMethodNotFoundException;
}
