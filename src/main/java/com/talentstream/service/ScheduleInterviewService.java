package com.talentstream.service;

import java.util.List;

import javax.persistence.EntityNotFoundException;
import com.talentstream.exception.CustomException;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import com.talentstream.dto.ScheduleInterviewDTO;
import com.talentstream.entity.ApplyJob;
import com.talentstream.entity.ScheduleInterview;
import com.talentstream.repository.ApplyJobRepository;
import com.talentstream.repository.ScheduleInterviewRepository;

@Service
public class ScheduleInterviewService {
	  final ModelMapper modelMapper = new ModelMapper();
	  @Autowired
	ApplyJobRepository applyJobRepository;

    @Autowired
    private ScheduleInterviewRepository scheduleInterviewRepository;

    public ScheduleInterviewDTO createScheduleInterview(Long applyJobId, ScheduleInterview scheduleInterview) {
       
    	try {
            ApplyJob applyJob = applyJobRepository.findById(applyJobId)
                    .orElseThrow(() -> new EntityNotFoundException("ApplyJob not found"));

            scheduleInterview.setApplyJob(applyJob);
            ScheduleInterview savedInterview = scheduleInterviewRepository.save(scheduleInterview);
            ScheduleInterviewDTO interviewDTO = modelMapper.map(savedInterview, ScheduleInterviewDTO.class);

            return interviewDTO;
        } catch (EntityNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new CustomException("Error creating schedule interview", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
   
    
    public List<ScheduleInterview> getScheduleInterviewsForCurrentDate() {
    	try {
            return scheduleInterviewRepository.findScheduleInterviewsForCurrentDate();
        } catch (Exception e) {
            throw new CustomException("Error retrieving schedule interviews for the current date", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public List<ScheduleInterview> getScheduleInterviewsByApplicantAndApplyJob(Long applicantId, Long applyJobId) {
    	 try {
             return scheduleInterviewRepository.findByApplicantIdAndApplyJobId(applicantId, applyJobId);
         } catch (Exception e) {
             throw new CustomException("Error retrieving schedule interviews by applicant and apply job", HttpStatus.INTERNAL_SERVER_ERROR);
         }
     }
    public void deleteScheduledInterview(Long scheduleInterviewId) {
        try {
            ScheduleInterview scheduleInterview = scheduleInterviewRepository.findById(scheduleInterviewId)
                    .orElseThrow(() -> new EntityNotFoundException("Scheduled Interview not found"));
 
            scheduleInterviewRepository.delete(scheduleInterview);
        } catch (EntityNotFoundException e) {
            throw e;
        } catch (Exception e) {
            throw new CustomException("Error deleting scheduled interview", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    }
