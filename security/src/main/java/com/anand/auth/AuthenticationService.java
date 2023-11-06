package com.anand.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.anand.config.JwtService;
import com.anand.repository.UserRepository;
import com.anand.user.Role;

import lombok.Builder;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
	
	private final UserRepository repository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	
	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		var user = repository.findByEmail(request.getEmail())
				.orElseThrow();
				var jwtToken = jwtService.generateToken(user);
		return AuthenticationResponse.builder()
				.token(jwtToken)
				.build();
	}

public AuthenticationResponse register(RegisterRequest request) {
	var user = com.anand.user.User.builder()
			.lastName(request.getLastName())
			.firstName(request.getFirstName())
			.email  (request.getEmail())
			.password(passwordEncoder.encode(request.getPassword()))
			.role(Role.USER)
			.build();
	repository.save(user);
	var jwtToken = jwtService.generateToken(user);
	return AuthenticationResponse.builder()
			.token(jwtToken)
			.build();
}

}
