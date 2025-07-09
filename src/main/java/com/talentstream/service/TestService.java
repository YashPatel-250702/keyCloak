package com.talentstream.service;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.talentstream.dto.TestDTO;
import com.talentstream.dto.TestQuestionDTO;
import com.talentstream.entity.Test;
import com.talentstream.entity.TestQuestions;
import com.talentstream.repository.TestRepository;

@Service
public class TestService {

    @Autowired
    private TestRepository testRepository;

    @Transactional
    public TestDTO createTest(TestDTO testDTO) {
        if (testRepository.findByTestNameIgnoreCase(testDTO.getTestName()).isPresent()) {
            throw new RuntimeException("Test with name '" + testDTO.getTestName() + "' already exists.");
        }

        Test test = convertToEntity(testDTO);
        Test savedTest = testRepository.save(test);
        return convertToDTO(savedTest);
    }

    public TestDTO getTestByName(String testName) {
        return testRepository.findByTestNameIgnoreCase(testName)
                .map(this::convertToDTO)
                .orElseThrow(() -> new IllegalArgumentException("Test with name '" + testName + "' not found"));
    }

    @Transactional
    public String addQuestionsToTest(String testName, List<TestQuestionDTO> questionDTOs) {
        Test test = testRepository.findByTestNameIgnoreCase(testName)
                .orElseThrow(() -> new RuntimeException("Test not found"));

        List<TestQuestions> existingQuestions = test.getQuestions();

        for (TestQuestionDTO questionDTO : questionDTOs) {
            TestQuestions question = new TestQuestions();
            question.setTest(test);
            question.setQuestion(questionDTO.getQuestion());
            question.setOptions(questionDTO.getOptions());
            question.setAnswer(questionDTO.getAnswer());
            question.setDifficulty(questionDTO.getDifficulty());

            existingQuestions.add(question);
        }

        test.setNumberOfQuestions(existingQuestions.size());
        testRepository.save(test);

        return questionDTOs.size() + " questions added successfully to Test Name: " + testName;
    }

    private Test convertToEntity(TestDTO testDTO) {
        Test test = new Test();
        test.setTestName(testDTO.getTestName());
        test.setDuration(testDTO.getDuration());
        test.setNumberOfQuestions(testDTO.getNumberOfQuestions());
        test.setTopicsCovered(testDTO.getTopicsCovered());

        List<TestQuestions> questions = Optional.ofNullable(testDTO.getQuestions())
                .orElse(List.of())
                .stream()
                .map(q -> {
                    TestQuestions question = new TestQuestions();
                    question.setQuestion(q.getQuestion());
                    question.setOptions(q.getOptions());
                    question.setAnswer(q.getAnswer());
                    question.setDifficulty(q.getDifficulty());
                    question.setTest(test);
                    return question;
                })
                .collect(Collectors.toList());

        test.setQuestions(questions);
        return test;
    }

    private TestDTO convertToDTO(Test test) {
        AtomicLong serialNumber = new AtomicLong(1);
        TestDTO testDTO = new TestDTO();
        testDTO.setId(test.getId());
        testDTO.setTestName(test.getTestName());
        testDTO.setDuration(test.getDuration());
        testDTO.setNumberOfQuestions(test.getNumberOfQuestions());
        testDTO.setTopicsCovered(test.getTopicsCovered());

        List<TestQuestionDTO> questionDTOs = test.getQuestions().stream()
                .map(q -> {
                    TestQuestionDTO dto = new TestQuestionDTO();
                    dto.setId(serialNumber.getAndIncrement());
                    dto.setQuestion(q.getQuestion());
                    dto.setOptions(q.getOptions());
                    dto.setAnswer(q.getAnswer());
                    dto.setDifficulty(q.getDifficulty());
                    return dto;
                })
                .collect(Collectors.toList());

        testDTO.setQuestions(questionDTOs);
        return testDTO;
    }
}