package com.iiht.lb.controller;


import com.iiht.lb.client.UserClient;
import com.iiht.lb.model.AuthenticationRequest;
import com.iiht.lb.model.AuthenticationResponse;
import com.iiht.lb.model.User;
import com.iiht.lb.service.JwtService;
import com.iiht.lb.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200")
public class UserController {

	@Autowired
	private UserClient userClient;

	@Autowired
	private JwtService jwtService;

//	@PostMapping("/register")
//	public ResponseEntity<Map<String, String>> registerUser(@RequestBody User user) {
//		try {
//			userService.registerUser(user);
//			Map<String, String> response = new HashMap<>();
//			response.put("message", "User registered successfully");
//
//			int caloriesIntake = CalorieCalculator.calculateCaloriesIntake(user);
//
//			Diet diet = new Diet();
//			diet.setUserId(user.getId());
//			diet.setCaloriesIntake(caloriesIntake); // Default value
//			diet.setDietaryPreference(user.getDietaryPreference());
//			restTemplate.postForObject("http://localhost:8081/DietPlanner/api/diets", diet, Diet.class);
//			return ResponseEntity.ok(response);
//
//		}
//		catch (Exception e) {
//			Map<String, String> response = new HashMap<>();
//			response.put("message", "User registered unsuccessfully");
//			return ResponseEntity.status(400).body(response);
//		}
//	}

//	@GetMapping("/check-username")
//	public ResponseEntity<Map<String, Boolean>> checkUsername(@RequestParam String username) {
//		boolean exists = userService.existsByUsername(username);
//		return ResponseEntity.ok(Map.of("exists", exists));
//	}

	@PostMapping("/login")
	public ResponseEntity<Map<String, String>> login(@RequestBody AuthenticationRequest user) {
		Map<String, String> response = new HashMap<>();
		Optional<User> usr = userClient.getUserByEmail(user.getUsername());
		if (usr.isPresent() && usr.get().getPassword().equals(user.getPassword())) {
			String token = jwtService.generateToken(user.getUsername());
			response.put("token", token); // Include the token in the response
			response.put("userId",usr.get().getId().toString());
			return ResponseEntity.ok(response);
		} else {
			response.put("error", "Invalid credentials");
			return ResponseEntity.status(401).body(response);
		}
	}

//	@GetMapping("/protected")
//	public String protectedResource() {
//		return "This is a protected resource!";
//	}

 	@GetMapping("/get")
	public String protectedResource() {
		return "This is a protected resource!";
	}
}