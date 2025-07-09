package com.talentstream.entity;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;

public class ApplicantProfileUpdateDTO {

    private List<ExperienceDetails> experienceDetails;

    @NotBlank(message = "Experience is required")
    @Pattern(regexp = "\\d+", message = "Experience must be numeric")
    private String experience;

    @NotBlank(message = "Qualification is required")
    private String qualification;

    @NotBlank(message = "Specialization is required")
    private String specialization;

    @NotEmpty(message = "Skills required cannot be empty")
    private Set<String> preferredJobLocations = new HashSet<>();
    @NotEmpty(message = "Skills required cannot be empty")
    private List<SkillDTO> skillsRequired;

    // Getters and Setters
    public String getExperience() {
        return experience;
    }

    public void setExperience(String experience) {
        this.experience = experience;
    }

    public String getQualification() {
        return qualification;
    }

    public void setQualification(String qualification) {
        this.qualification = qualification;
    }

    public String getSpecialization() {
        return specialization;
    }

    public void setSpecialization(String specialization) {
        this.specialization = specialization;
    }

    public Set<String> getPreferredJobLocations() {
        return preferredJobLocations;
    }

    public void setPreferredJobLocations(Set<String> preferredJobLocations) {
        this.preferredJobLocations = preferredJobLocations;
    }

    public List<SkillDTO> getSkillsRequired() {
        return skillsRequired;
    }

    public void setSkillsRequired(List<SkillDTO> skillsRequired) {
        this.skillsRequired = skillsRequired;
    }

    public static class SkillDTO {
        private Long id;
        private String skillName;
        private double experience;

        // Getters and Setters

        public Long getId() {
            return id;
        }

        public void setId(Long id) {
            this.id = id;
        }

        public String getSkillName() {
            return skillName;
        }

        public void setSkillName(String skillName) {
            this.skillName = skillName;
        }

        public double getExperience() {
            return experience;
        }

        public void setExperience(double experience) {
            this.experience = experience;
        }
    }
}
