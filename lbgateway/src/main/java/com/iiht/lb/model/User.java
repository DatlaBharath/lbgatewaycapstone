package com.iiht.lb.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Data
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class User {
    private Long id;
    private  String email;
    private String password;
    private String fullName;
    private String Mobile;
}
