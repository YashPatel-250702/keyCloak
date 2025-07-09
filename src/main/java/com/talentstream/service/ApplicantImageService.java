package com.talentstream.service;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
import com.talentstream.AwsSecretsManagerUtil;
import com.talentstream.entity.Applicant;
import com.talentstream.exception.CustomException;
import com.talentstream.repository.ApplicantImageRepository;
import com.talentstream.repository.RegisterRepository;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.springframework.core.io.InputStreamResource;

@Service
public class ApplicantImageService {

	private final Path root = Paths.get("applicantprofileimages");

	@Autowired
	private ApplicantImageRepository applicantImageRepository;

	@Autowired
	private RegisterRepository applicantService;

	public ApplicantImageService() throws IOException {

	}

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
	// Uploads an image for the specified applicant, validating size and type;
	// throws CustomException for issues.
	public String uploadImage(long applicantId, MultipartFile imageFile) {

		if (imageFile.getSize() > 5 * 1024 * 1024) {
			throw new CustomException("File size should be less than 5MB.", HttpStatus.BAD_REQUEST);
		}
		String contentType = imageFile.getContentType();
		if (!"image/jpeg".equals(contentType) && !"image/png".equals(contentType)) {
			throw new CustomException("Only JPG and PNG file types are allowed.", HttpStatus.BAD_REQUEST);
		}

		Applicant applicant = applicantService.findById(applicantId); // Assuming findById in RegisterRepository
		if (applicant == null) {

			throw new CustomException("Applicant not found for ID: " + applicantId, HttpStatus.NOT_FOUND);

		} else {

			// Logic for S3 upload
			String objectKey = String.valueOf(applicantId) + ".jpg"; // Generate unique object key

			try {
				AmazonS3 s3Client = initializeS3Client();

				s3Client.putObject(
						new PutObjectRequest(bucketName, objectKey, imageFile.getInputStream(),
								createObjectMetadata(imageFile)));

				return objectKey;

			} catch (AmazonServiceException ase) {

				throw new RuntimeException("Failed to upload image to S3", ase);
			} catch (IOException e) {

				throw new RuntimeException("Error processing image file", e);
			}
		}
	}

	// Creates metadata for the given image file, including content type and size;
	// throws IOException for errors.
	private ObjectMetadata createObjectMetadata(MultipartFile imageFile) throws IOException {
		ObjectMetadata objectMetadata = new ObjectMetadata();
		objectMetadata.setContentType(imageFile.getContentType());
		objectMetadata.setContentLength(imageFile.getSize());
		return objectMetadata;
	}

	// Retrieves the profile picture of the applicant with the specified ID from S3;
	// throws RuntimeException for errors.
	public ResponseEntity<Resource> getProfilePicByApplicantId(long applicantId) {
		try {

			String objectKey = String.valueOf(applicantId) + ".jpg";

			AmazonS3 s3Client = initializeS3Client();

			S3Object s3Object = s3Client.getObject(new GetObjectRequest(bucketName, objectKey));
			S3ObjectInputStream inputStream = s3Object.getObjectContent();

			MediaType mediaType;
			if (objectKey.toLowerCase().endsWith(".png")) {
				mediaType = MediaType.IMAGE_PNG;
			} else if (objectKey.toLowerCase().endsWith(".jpg") || objectKey.toLowerCase().endsWith(".jpeg")) {
				mediaType = MediaType.IMAGE_JPEG;
			} else {
				throw new RuntimeException("Unsupported image file format for applicant ID: " + applicantId);
			}

			InputStreamResource resource = new InputStreamResource(inputStream);

			return ResponseEntity.ok()
					.contentType(mediaType)
					.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + objectKey + "\"")
					.body(resource);

		} catch (Exception e) {
			String errorMessage = "Internal Server Error";
			InputStreamResource errorResource = new InputStreamResource(
					new ByteArrayInputStream(errorMessage.getBytes()));
			System.out.println(e.getMessage());
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.contentType(MediaType.TEXT_PLAIN)
					.body(errorResource);
		}
	}

}
