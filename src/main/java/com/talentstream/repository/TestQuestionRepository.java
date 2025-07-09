package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.talentstream.entity.TestQuestions;

public interface TestQuestionRepository extends JpaRepository<TestQuestions, Long> {

}