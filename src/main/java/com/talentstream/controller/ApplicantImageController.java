package com.talentstream.controller;

import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
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
import com.talentstream.service.ApplicantImageService;
 
 
@RestController
@RequestMapping("/applicant-image")
public class ApplicantImageController {
	
	@Autowired
    private ApplicantImageService applicantImageService;
		
    @PostMapping("/{applicantId}/upload")
    public String fileUpload(@PathVariable Long applicantId,@RequestParam("photo")MultipartFile photo)
    {
    	 try {
    	        String filename = this.applicantImageService.uploadImage(applicantId, photo);
    	        return "Image uploaded successfully. Filename: " + filename;
    	    } catch (CustomException ce) {
    	        return ce.getMessage();
    	    } catch (UnsupportedFileTypeException e) {
    	        return "Only JPG and PNG file types are allowed.";
    	    } catch (MaxUploadSizeExceededException e) {
    	        return "File size should be less than 1MB.";
    	    } catch (Exception e) {
    	        e.printStackTrace();
    	        return "Image not uploaded successfully";
    	    }
    }
    @GetMapping("/getphoto/{applicantId}")
    public ResponseEntity<Resource> getProfilePic(@PathVariable long applicantId) throws IOException {
        return applicantImageService.getProfilePicByApplicantId(applicantId);
    }
	    @GetMapping("/getphoto1/{applicantId}")
    public ResponseEntity<Resource> getProfilePic1(@PathVariable long applicantId) throws IOException {
        return applicantImageService.getProfilePicByApplicantId(applicantId);
    }
    
}
