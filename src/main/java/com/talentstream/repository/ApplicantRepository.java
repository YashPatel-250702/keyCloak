package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.talentstream.entity.Applicant;

@Repository
public interface ApplicantRepository extends JpaRepository<Applicant, Long> {

}
