package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.talentstream.entity.RecuriterSkills;

 

@Repository
public interface RecuriterSkillsRepository extends JpaRepository<RecuriterSkills, Long> {
 
	RecuriterSkills findBySkillName(String skillName);
   
}