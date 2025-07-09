package com.talentstream.dto;

public class SkillDTO {
	
	private String skillName;

    public SkillDTO(String skillName) {
        this.skillName = skillName;
    }

    public String getSkillName() {
        return skillName;
    }

    public void setSkillName(String skillName) {
        this.skillName = skillName;
    }

    @Override
    public String toString() {
        return skillName;
    }

}
