package com.Asti.jobhunt.controller;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Asti.jobhunt.constants.ERole;
import com.Asti.jobhunt.exception.AccessDeniedException;
import com.Asti.jobhunt.models.Role;
import com.Asti.jobhunt.models.User;
import com.Asti.jobhunt.payloadRequest.SignupRequest;
import com.Asti.jobhunt.repository.RoleRepository;
import com.Asti.jobhunt.repository.UserRepository;
import com.Asti.jobhunt.response.MessageResponse;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class Authcontroller {

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	/**
	 * Author: Prakash M 
	 * Date: April 17, 2024
	 */
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {

		if (userRepository.existsByUsername(signUpRequest.getUsername()))
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
		if (userRepository.existsByEmail(signUpRequest.getEmail()))
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));

		User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(),
				encoder.encode(signUpRequest.getPassword()));
		Set<String> strRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();

		if (strRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new AccessDeniedException("Error: Role is not found."));
			roles.add(userRole);
		} else {
			strRoles.forEach(role -> {
				switch (role) {
				case "ROLE_ADMIN":
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new AccessDeniedException("Error: Role is not found."));
					roles.add(adminRole);
				case "ROLE_MODERATOR":
					Role modeRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new AccessDeniedException("Error: Role is not found."));
					roles.add(modeRole);

					break;
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new AccessDeniedException("Error: Role is not found"));
					roles.add(userRole);
				}
			});
		}
		user.setRoles(roles);
		userRepository.save(user);

		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}

}
