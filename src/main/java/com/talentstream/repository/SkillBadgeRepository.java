package com.talentstream.repository;
import org.springframework.data.jpa.repository.JpaRepository;

import com.talentstream.entity.SkillBadge;

public interface SkillBadgeRepository extends JpaRepository<SkillBadge, Long> {
	SkillBadge findByName(String name);
}
