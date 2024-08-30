package com.iiht.lb.client;

import com.iiht.lb.model.User;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.util.Optional;

@FeignClient(name = "user-service",url="http://localhost:7777")
public interface UserClient {
    @GetMapping("/users/user/{email}")
    Optional<User> getUserByEmail(@PathVariable String email);
}
