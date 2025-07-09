package com.talentstream.dto;
 
import java.util.List;
 
 
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
 
 
public class CompanyProfileDTO {
	private Long id;
	@NotBlank(message = "Company name cannot be blank")
	@Size(min = 3, message = "Company name must be at least 3 characters")
	private String companyName;
	@NotBlank(message = "Website cannot be blank")
	@Pattern(regexp = "^(.+)\\.(com|in|org)$", message = "Website must end with .com, .in, or .org")
	private String website;
	private String phoneNumber;
	private String email;
	private String headOffice;
	@NotBlank(message = "about company cannot be blank")
	@Size(min = 50,  message = "please enter atleast 50 characters")
	@Size(max = 500, message = "characters limit exceeded , please enter below 500 characters")
	private String aboutCompany;
 
	@Size(min = 1, message = "Logo cannot be empty")
	private byte[] logo;
	private List<String> socialProfiles;
	
	public Long getId() {
		return id;
	}
 
	public void setId(Long id) {
		this.id = id;
	}
 
	public String getCompanyName() {
		return companyName;
	}
 
	public void setCompanyName(String companyName) {
		this.companyName = companyName;
	}
 
	public String getWebsite() {
		return website;
	}
 
	public void setWebsite(String website) {
		this.website = website;
	}
 
	public String getPhoneNumber() {
		return phoneNumber;
	}
 
	public void setPhoneNumber(String phoneNumber) {
		this.phoneNumber = phoneNumber;
	}
 
	public String getEmail() {
		return email;
	}
 
	public void setEmail(String email) {
		this.email = email;
	}
 
	public String getHeadOffice() {
		return headOffice;
	}
 
	public void setHeadOffice(String headOffice) {
		this.headOffice = headOffice;
	}
	public String getAboutCompany() {
		return aboutCompany;
	}
 
	public void setAboutCompany(String aboutCompany) {
		this.aboutCompany = aboutCompany;
	}
 
 
	public List<String> getSocialProfiles() {
		return socialProfiles;
	}
 
	public void setSocialProfiles(List<String> socialProfiles) {
		this.socialProfiles = socialProfiles;
	}
 
	public byte[] getLogo() {
		return logo;
	}
 
	public void setLogo(byte[] logo) {
		this.logo = logo;
	}
 
}
 