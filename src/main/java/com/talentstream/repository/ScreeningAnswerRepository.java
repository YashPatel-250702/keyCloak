package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.talentstream.entity.ScreeningAnswer;

@Repository
public interface ScreeningAnswerRepository extends JpaRepository<ScreeningAnswer, Long> {
}
