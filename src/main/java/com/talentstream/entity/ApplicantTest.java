package com.talentstream.entity;

import javax.persistence.*;

import com.fasterxml.jackson.annotation.JsonBackReference;

import java.time.LocalDateTime;

@Entity
@Table(name = "applicant_tests")
public class ApplicantTest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "test_name", nullable = false)
    private String testName;

    @Column(name = "test_score", nullable = false)
    private Double testScore;

    @Column(name = "test_status", nullable = false)
    private String testStatus; // P (Pass) / F (Fail)

    @Column(name = "test_date_and_time", nullable = false)
    private LocalDateTime testDateTime;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "applicant_id", nullable = false)
    @JsonBackReference
    private Applicant applicant;
    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }


    public String getTestName() {
        return testName;
    }

    public void setTestName(String testName) {
        this.testName = testName;
    }

    public Applicant getApplicant() {
        return applicant;
    }

    public void setApplicant(Applicant applicant) {
        this.applicant = applicant;
    }

    public Double getTestScore() {
        return testScore;
    }

    public void setTestScore(Double testScore) {
        this.testScore = testScore;
    }

    public String getTestStatus() {
        return testStatus;
    }

    public void setTestStatus(String testStatus) {
        this.testStatus = testStatus;
    }

    public LocalDateTime getTestDateTime() {
        return testDateTime;
    }

    public void setTestDateTime(LocalDateTime testDateTime) {
        this.testDateTime = testDateTime;
    }

    // Method to set current date and time before persisting
    @PrePersist
    protected void onCreate() {
        this.testDateTime = LocalDateTime.now();
    }
}
