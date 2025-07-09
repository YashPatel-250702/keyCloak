package com.talentstream.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import com.talentstream.dto.ContactDetailsDTO;
import com.talentstream.entity.ContactDetails;
import com.talentstream.repository.ContactDetailsRepository;

@Service
public class ContactService {

	@Autowired
	private ContactDetailsRepository contactDetailsRepository;

	// Saves contact details and returns a success response.
	public ResponseEntity<String> saveContactDetails(ContactDetailsDTO contactDetails) {
		ContactDetails contactdetails = mapContactDetailsDTOToContactDetails(contactDetails);
		contactDetailsRepository.save(contactdetails);
		return ResponseEntity.ok("Message sent successfully");
	}

	// Maps a ContactDetailsDTO to a ContactDetails entity.
	private ContactDetails mapContactDetailsDTOToContactDetails(ContactDetailsDTO contactDetails) {
		ContactDetails cd = new ContactDetails();
		cd.setName(contactDetails.getName());
		cd.setEmail(contactDetails.getEmail());
		cd.setSubject(contactDetails.getSubject());
		cd.setQuestions(contactDetails.getQuestions());
		return cd;
	}

	// Retrieves all contact messages from the repository.
	public List<ContactDetails> getMessages() {
		return contactDetailsRepository.findAll();
	}
}