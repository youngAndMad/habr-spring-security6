package kz.danekerscode.habrspringsecurity6.repository;

import kz.danekerscode.habrspringsecurity6.model.entity.User;
import kz.danekerscode.habrspringsecurity6.model.enums.AuthType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    boolean existsByEmailAndAuthType(String email, AuthType authType);

    Optional<User> findByEmailAndAuthType(String email, AuthType authType);
}