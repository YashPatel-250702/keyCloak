package com.talentstream.entity;

import java.util.List;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;

import org.hibernate.annotations.Type;
import org.hibernate.annotations.TypeDef;

import com.vladmihalcea.hibernate.type.json.JsonBinaryType;

@Entity
@TypeDef(name = "jsonb", typeClass = JsonBinaryType.class) 
public class TestQuestions {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(columnDefinition = "TEXT")
    private String question;

//    @ElementCollection
//    private List<String> options;
    
    @Type(type = "jsonb")
    @Column(columnDefinition = "jsonb") 
    private List<String> options;

    private String answer;
    private String difficulty;

    @ManyToOne
    @JoinColumn(name = "test_id", nullable = false)
    private Test test;

    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getQuestion() {
        return question;
    }
    public void setQuestion(String question) {
        this.question = question;
    }
    public List<String> getOptions() {
        return options;
    }
    public void setOptions(List<String> options) {
        this.options = options;
    }
    public String getAnswer() {
        return answer;
    }
    public Test getTest() {
		return test;
	}
	public void setTest(Test test) {
		this.test = test;
	}
	public void setAnswer(String answer) {
        this.answer = answer;
    }
	public String getDifficulty() {
		return difficulty;
	}
	public void setDifficulty(String difficulty) {
		this.difficulty = difficulty;
	}
	
	
   
}