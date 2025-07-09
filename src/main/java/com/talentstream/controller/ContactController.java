package com.talentstream.controller;

import java.util.List;

import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.util.*;

import com.talentstream.dto.ContactDetailsDTO;
import com.talentstream.entity.ContactDetails;
import com.talentstream.service.ContactService;

@RestController
public class ContactController {

	private static final Logger logger = LoggerFactory.getLogger(ContactController.class);

	@Autowired
	private ContactService contactService;

	@PostMapping("/send-message")
	public ResponseEntity<Map<String, String>> sendMessage(@Valid @RequestBody ContactDetailsDTO contactDetails,
			BindingResult bindingResult) {
		if (bindingResult.hasErrors()) {
			// Handle validation errors
			Map<String, String> fieldErrors = new LinkedHashMap<>();

			bindingResult.getFieldErrors().forEach(fieldError -> {
				String fieldName = fieldError.getField();
				String errorMessage = fieldError.getDefaultMessage();
				fieldErrors.put(fieldName, errorMessage);
			});
			logger.warn("Validation errors occurred while sending message: {}", fieldErrors);
			return ResponseEntity.badRequest().body(fieldErrors);
		}

		contactService.saveContactDetails(contactDetails);
		logger.info("Message sent successfully");
		return ResponseEntity.ok(Collections.singletonMap("message", "Message sent successfully"));
	}

	@GetMapping("/get-messages")
	public ResponseEntity<List<ContactDetails>> getMessages() {

		List<ContactDetails> contactDetails = contactService.getMessages();
		logger.info("Messages retrieved successfully");
		return ResponseEntity.ok(contactDetails);
	}

}
