package com.system.abcrestaurant.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
public class Address {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String streetAddress;

    @Column(nullable = false)
    private String city;

    @Column(nullable = false)
    private String stateProvince;

    @Column(nullable = false)
    private String postalCode;

    @Column(nullable = false)
    private String country;
}
