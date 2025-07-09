package com.talentstream.repository;

import com.talentstream.entity.ApplicantProfile;
import com.talentstream.entity.ApplicantSkills;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ApplicantSkillsRepository extends JpaRepository<ApplicantSkills, Long> {

	 List<ApplicantSkills> findBySkillName(String skillName);
}
