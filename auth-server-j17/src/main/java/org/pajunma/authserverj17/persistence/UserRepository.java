package org.pajunma.authserverj17.persistence;

import org.pajunma.authserverj17.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<AppUser, Integer> {

    AppUser findByUsername(String username);
}
