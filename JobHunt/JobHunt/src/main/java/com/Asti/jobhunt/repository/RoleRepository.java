package com.Asti.jobhunt.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.Asti.jobhunt.constants.ERole;
import com.Asti.jobhunt.models.Role;

public interface RoleRepository extends JpaRepository<Role, Integer>
{

	Optional<Role> findByName(ERole roleUser);

}
