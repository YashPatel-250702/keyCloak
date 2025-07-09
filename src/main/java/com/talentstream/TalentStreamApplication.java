package com.talentstream;

import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import java.io.IOException;
import java.net.HttpURLConnection;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SpringBootApplication
@EnableWebMvc
@EnableScheduling
public class TalentStreamApplication {
	private static final Logger logger = LoggerFactory.getLogger(TalentStreamApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(TalentStreamApplication.class, args);
	}

	@Bean
	public RestTemplate createRestTemplate() {
		// Create a trust manager that trusts all certificates
		TrustManager[] trustAllCerts = new TrustManager[] {
				new X509TrustManager() {
					public java.security.cert.X509Certificate[] getAcceptedIssuers() {
						return null;
					}

					public void checkClientTrusted(
							java.security.cert.X509Certificate[] certs, String authType) {
					}

					public void checkServerTrusted(
							java.security.cert.X509Certificate[] certs, String authType) {
					}
				}
		};

		try {
			// Create an SSL context with the above trust manager
			SSLContext sslContext = SSLContext.getInstance("SSL");
			sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

			// Configure a SimpleClientHttpRequestFactory with the custom SSL context
			SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory() {
				@Override
				protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
					if (connection instanceof HttpsURLConnection) {
						((HttpsURLConnection) connection).setSSLSocketFactory(sslContext.getSocketFactory());
					}
					super.prepareConnection(connection, httpMethod);
				}
			};
			factory.setConnectTimeout(10000);
			factory.setReadTimeout(10000);

			// Create a RestTemplate with the custom request factory
			return new RestTemplate(factory);
		} catch (Exception ex) {
			throw new RuntimeException("Error while configuring RestTemplate with custom SSL context", ex);
		}
	}

	@Bean
	public Docket api() {
		return new Docket(DocumentationType.SWAGGER_2)
				.select()
				.apis(RequestHandlerSelectors.basePackage("com.talentstream"))
				.paths(PathSelectors.any())
				.build();
	}

}