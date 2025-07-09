package com.talentstream.entity;

import javax.persistence.*;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonManagedReference;

import java.util.HashSet;
import java.util.Set;

@Entity
public class ScreeningQuestion {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String questionText;

    @ManyToOne
    @JoinColumn(name = "job_id", nullable = false)
    @JsonBackReference
    private Job job;

    @OneToMany(mappedBy = "screeningQuestion", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonManagedReference
    private Set<ScreeningAnswer> answers = new HashSet<>();

    // Getters and setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getQuestionText() {
        return questionText;
    }

    public void setQuestionText(String questionText) {
        this.questionText = questionText;
    }

    public Job getJob() {
        return job;
    }

    public void setJob(Job job) {
        this.job = job;
    }

    public Set<ScreeningAnswer> getAnswers() {
        return answers;
    }

    public void setAnswers(Set<ScreeningAnswer> answers) {
        this.answers = answers;
    }

    public void addAnswer(ScreeningAnswer answer) {
        answers.add(answer);
        answer.setScreeningQuestion(this);
    }

    public void removeAnswer(ScreeningAnswer answer) {
        answers.remove(answer);
        answer.setScreeningQuestion(null);
    }
}
