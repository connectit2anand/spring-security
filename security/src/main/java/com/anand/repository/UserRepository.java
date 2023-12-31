package com.anand.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.anand.user.User;

public interface UserRepository extends JpaRepository<User, Integer>{
	
	Optional<User> findByEmail(String email);
}
