package com.talentstream.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.http.ResponseEntity;
import com.talentstream.entity.Applicant;
import com.talentstream.entity.ApplicantResume;
import com.talentstream.exception.CustomException;
import com.talentstream.repository.ApplicantResumeRepository;
import com.talentstream.repository.RegisterRepository;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.net.MalformedURLException;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

@Service
public class ApplicantResumeService {

    @Autowired
    private ApplicantResumeRepository applicantResumeRepository;

    @Autowired
    private RegisterRepository applicantService;

    // Uploads a PDF resume for the specified applicant; validates file size and
    // type; throws CustomException for errors.
    public String UploadPdf(long applicantId, MultipartFile pdfFile) throws IOException {

        if (pdfFile.getSize() > 5 * 1024 * 1024) {
            throw new CustomException("File size should be less than 5MB.", HttpStatus.BAD_REQUEST);
        }

        String contentType = pdfFile.getContentType();
        if (!"application/pdf".equals(contentType)) {
            throw new CustomException("Only PDF file types are allowed.", HttpStatus.BAD_REQUEST);
        }

        Applicant applicant = applicantService.getApplicantById(applicantId);
        if (applicant == null)
            throw new CustomException("Applicant not found for ID: " + applicantId, HttpStatus.NOT_FOUND);
        else {
            ApplicantResume existingpdf = applicantResumeRepository.findByApplicant(applicant);
            if (existingpdf != null) {
                String folderPath = "src/main/resources/applicant/resumes";
                String existingFileName = existingpdf.getPdfname();
                String existingFilePath = Paths.get(folderPath, existingFileName).toString();

                try {
                    Files.deleteIfExists(Paths.get(existingFilePath));
                } catch (IOException e) {
                    e.printStackTrace();
                }

                String name = StringUtils.cleanPath(pdfFile.getOriginalFilename());
                String newFileName = applicantId + "_" + name;
                String filePath = Paths.get(folderPath, newFileName).toString();
                try {
                    Files.copy(pdfFile.getInputStream(), Paths.get(filePath), StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e) {
                    e.printStackTrace();
                }

                existingpdf.setPdfname(newFileName);
                applicantResumeRepository.save(existingpdf);

                return name;
            } else {

                String name = StringUtils.cleanPath(pdfFile.getOriginalFilename());
                String fileName = applicantId + "_" + name;
                String folderPath = "src/main/resources/applicant/resumes";
                String filePath = Paths.get(folderPath, fileName).toString();
                try {
                    Files.createDirectories(Paths.get(folderPath));
                    Files.copy(pdfFile.getInputStream(), Paths.get(filePath), StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException e) {
                    e.printStackTrace();
                }
                ApplicantResume applicantResume = new ApplicantResume();
                applicantResume.setPdfname(fileName);
                applicantResume.setApplicant(applicant);
                applicantResumeRepository.save(applicantResume);

                return name;
            }
        }
    }

    // Retrieves the resume for the specified applicant by ID; returns a Resource
    // for the PDF file; throws CustomException if not found.
    public ResponseEntity<org.springframework.core.io.Resource> getResumeByApplicantId(long applicantId)
            throws IOException {

        ApplicantResume applicantResume = applicantResumeRepository.findByApplicantId(applicantId);
        if (applicantResume != null) {
            String fileName = applicantResume.getPdfname();
            Path filePath = Paths.get("src/main/resources/applicant/resumes", fileName);
            try {
                UrlResource resource = new UrlResource(filePath.toUri());

                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_PDF)
                        .header(HttpHeaders.CONTENT_DISPOSITION,
                                "attachment; filename=\"" + resource.getFilename() + "\"")
                        .body(resource);
            } catch (MalformedURLException e) {
                throw new RuntimeException("Error reading the resume file for applicant ID: " + applicantId, e);
            }
        } else {
            throw new CustomException("Resume not found for applicant ID: " + applicantId, HttpStatus.NOT_FOUND);
        }
    }

}
