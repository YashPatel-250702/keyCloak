package com.talentstream.controller;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartFile;

import com.talentstream.exception.CustomException;
import com.talentstream.exception.UnsupportedFileTypeException;
import com.talentstream.service.CompanyLogoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/recruiters")
public class CompanyLogoController {
	private static final Logger logger = LoggerFactory.getLogger(CompanyLogoController.class);
	@Autowired
	private CompanyLogoService companyLogoService;

	@PostMapping("/companylogo/upload/{jobRecruiterId}")
	public String fileUpload(@PathVariable Long jobRecruiterId, @RequestParam MultipartFile logoFile) {
		try {
			String filename = companyLogoService.saveCompanyLogo(jobRecruiterId, logoFile);
			logger.info("Company logo uploaded successfully: {}", filename);
			return filename + " Image uploaded successfully";
		} catch (CustomException ce) {
			logger.error("Error occurred while uploading company logo: {}", ce.getMessage());
			return ce.getMessage();
		} catch (UnsupportedFileTypeException e) {
			logger.error("Unsupported file type during company logo upload");
			return "Only JPG and PNG file types are allowed.";
		} catch (MaxUploadSizeExceededException e) {
			logger.error("Max upload size exceeded during company logo upload");
			return "File size should be less than 1MB.";
		} catch (IOException e) {
			e.printStackTrace();
			logger.error("Error occurred while uploading company logo", e);
			return "Image not uploaded successfully";
		}
	}

	@GetMapping("/companylogo/download/{jobRecruiterId}")
	public ResponseEntity<byte[]> getCompanyLogo(@PathVariable Long jobRecruiterId) {
		try {
			byte[] imageBytes = companyLogoService.getCompanyLogo(jobRecruiterId);
			logger.info("Company logo downloaded successfully for recruiter ID: {}", jobRecruiterId);
			return ResponseEntity.ok()
					.contentType(MediaType.IMAGE_JPEG)
					.body(imageBytes);

		} catch (CustomException ce) {
			// Handle exception appropriately, e.g., return a 404 Not Found response
			logger.error("Error occurred while downloading company logo for recruiter ID: {}", jobRecruiterId);
			return ResponseEntity.status(ce.getStatus()).body(null);
		}
	}
}