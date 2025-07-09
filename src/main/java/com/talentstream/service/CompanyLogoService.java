package com.talentstream.service;

import java.io.ByteArrayInputStream;

import java.io.IOException;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

import org.springframework.web.multipart.MultipartFile;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectInputStream;
import com.amazonaws.util.IOUtils;
import com.talentstream.AwsSecretsManagerUtil;
import com.talentstream.entity.JobRecruiter;

import com.talentstream.exception.CustomException;

import com.talentstream.repository.CompanyLogoRepository;

import com.talentstream.repository.JobRecruiterRepository;

@Service
public class CompanyLogoService {

	private static final long MAX_FILE_SIZE_BYTES = 1024 * 1024; // 1 MB = 1024 * 1024 bytes
	private static final String[] ALLOWED_EXTENSIONS = { "jpg", "jpeg", "png", "gif" };

	@Autowired
	private CompanyLogoRepository companyLogoRepository;
	@Autowired
	private JobRecruiterRepository jobRecruiterRepository;

	@Autowired
    private AwsSecretsManagerUtil secretsManagerUtil;

    
    private String bucketName;

    private String getSecret() {
        return secretsManagerUtil.getSecret();
    }

    private AmazonS3 initializeS3Client() {
       
        String secret = getSecret();

        JSONObject jsonObject = new JSONObject(secret);
        String accessKey = jsonObject.getString("AWS_ACCESS_KEY_ID");
        String secretKey = jsonObject.getString("AWS_SECRET_ACCESS_KEY");
        bucketName = jsonObject.getString("AWS_S3_BUCKET_NAME");
        String region = jsonObject.getString("AWS_REGION");
        
        
        BasicAWSCredentials awsCredentials = new BasicAWSCredentials(accessKey, secretKey);
        return AmazonS3ClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(awsCredentials))
                .withRegion(Regions.fromName(region))
                .build();
    }

	// Validates the image file and uploads it to S3, returning the object key if
	// successful.
	public String saveCompanyLogo(long jobRecruiterId, MultipartFile imageFile) throws IOException {

		if (imageFile.getSize() > 1 * 1024 * 1024) {
			throw new CustomException("File size should be less than 1MB.", HttpStatus.BAD_REQUEST);
		}
		String contentType = imageFile.getContentType();
		if (!"image/jpeg".equals(contentType) && !"image/png".equals(contentType)) {
			throw new CustomException("Only JPG and PNG file types are allowed.", HttpStatus.BAD_REQUEST);
		}

		JobRecruiter recruiter = jobRecruiterRepository.findByRecruiterId(jobRecruiterId);
		if (recruiter == null) {
			throw new CustomException("Recruiter not found for ID: " + jobRecruiterId, HttpStatus.NOT_FOUND);
		} else {

			// Logic for S3 upload

			String objectKey = String.valueOf(jobRecruiterId) + ".jpg"; // Generate unique object key

			try {
				AmazonS3 s3Client = initializeS3Client();

				s3Client.putObject(
						new PutObjectRequest(bucketName, objectKey, imageFile.getInputStream(),
								createObjectMetadata(imageFile)));

				return objectKey; // Return the object key for reference

			} catch (AmazonServiceException ase) {
				// Handle exceptions appropriately, e.g., log the error
				throw new RuntimeException("Failed to upload image to S3", ase);
			} catch (IOException e) {
				// Handle potential IO exceptions during stream processing
				throw new RuntimeException("Error processing image file", e);
			}
		}

	}

	// Creates and returns ObjectMetadata for the uploaded image file, including its
	// content type and size.
	private ObjectMetadata createObjectMetadata(MultipartFile imageFile) throws IOException {
		ObjectMetadata objectMetadata = new ObjectMetadata();
		objectMetadata.setContentType(imageFile.getContentType());
		objectMetadata.setContentLength(imageFile.getSize());
		return objectMetadata;
	}

	// Retrieves the company logo from S3 as a byte array based on the recruiter ID.
	public byte[] getCompanyLogo(long jobRecruiterId) {
		try {

			String objectKey = String.valueOf(jobRecruiterId) + ".jpg";

			AmazonS3 s3Client = initializeS3Client();

			S3Object s3Object = s3Client.getObject(new GetObjectRequest(bucketName, objectKey));
			S3ObjectInputStream inputStream = s3Object.getObjectContent();

			MediaType mediaType;
			if (objectKey.toLowerCase().endsWith(".png")) {
				mediaType = MediaType.IMAGE_PNG;
			} else if (objectKey.toLowerCase().endsWith(".jpg") || objectKey.toLowerCase().endsWith(".jpeg")) {
				mediaType = MediaType.IMAGE_JPEG;
			} else {
				throw new RuntimeException("Unsupported image file format for applicant ID: " + jobRecruiterId);
			}

			byte[] bytes = IOUtils.toByteArray(inputStream); // Convert input stream to byte array

			return bytes;

		} catch (Exception e) {
			String errorMessage = "Internal Server Error";
			byte[] errorBytes = errorMessage.getBytes();
			ByteArrayInputStream errorStream = new ByteArrayInputStream(errorBytes);

			System.out.println(e.getMessage());
			return errorBytes;
		}

	}
}
