package com.iiht.lb.controller;


import com.iiht.lb.model.AuthenticationRequest;
import com.iiht.lb.model.AuthenticationResponse;
import com.iiht.lb.service.JwtUtil;
import com.iiht.lb.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;


@CrossOrigin(origins = "http://localhost:4200")
@RestController
public class UserResource {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private MyUserDetailsService userDetailsService;

	@Autowired
	JwtUtil jwtutil;

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest)
			throws Exception {
		System.out.println(authenticationRequest.getUsername() + authenticationRequest.getPassword());
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
					authenticationRequest.getUsername(), authenticationRequest.getPassword()));
		} catch (BadCredentialsException e) {

			throw new Exception("Incorrect username or password", e);
		}

		final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
		final String jwt = jwtutil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(jwt));

	}
	@CrossOrigin(origins = "http://localhost:4200")
	@GetMapping
	@RequestMapping("/greet")
	public String greet() {
		return "working";
	}

	@GetMapping
	@RequestMapping("/admin")
	public String greetAdmin() {
		return "Admin@Work";
	}

	@GetMapping
	@RequestMapping("/user")
	public String greetUser() {
		return "User@Work";
	}
}