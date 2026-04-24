package com.spring.edumate.entity;


import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "black_tokens")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class BlackToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String token;
}