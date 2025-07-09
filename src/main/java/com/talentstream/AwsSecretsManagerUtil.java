package com.talentstream;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AwsSecretsManagerUtil {

	public static String getSecret() {
		try {
			String secrets = System.getenv("AWS_ACCESS_KEY_ID");
			JSONObject jsonObject = new JSONObject(secrets);
			String accessKey = jsonObject.getString("AWS_ACCESS_KEY_ID");
			String secretKey = jsonObject.getString("AWS_SECRET_ACCESS_KEY");
			String region1 = jsonObject.getString("AWS_REGION");
			Region region = Region.of(region1);

			if (accessKey == null || secretKey == null) {
				System.err.println("AWS credentials are not set in environment variables.");
				return null;
			}
			return secrets;
		} catch (Exception e) {
			System.err.println("An error occurred: " + e.getMessage());
			return null;
		}
	}

}

    
