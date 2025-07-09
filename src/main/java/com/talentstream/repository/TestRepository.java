package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.talentstream.entity.Test;
import java.util.Optional;

public interface TestRepository extends JpaRepository<Test, Long> {
    Optional<Test> findByTestNameIgnoreCase(String testName);
}