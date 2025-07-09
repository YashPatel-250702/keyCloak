package com.talentstream.entity;
import javax.persistence.Embeddable;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;


@Embeddable
public class BasicDetails {
	    @NotBlank(message = "Firstname is required.")
        @Pattern(regexp = "^[a-zA-Z ]{3,19}$", message = "invalid username")
        @Size(min = 3, message = "First name must be at least 3 characters long.")
	    private String firstName;
	    @NotBlank(message = "Lastname is required.")
	    @Pattern(regexp = "^[a-zA-Z ]{3,19}$", message = "invalid username")
	    @Size(min = 3, message = "Last name must be at least 3 characters long.")
	    private String lastName;

	    private String dateOfBirth;
	    private String address;
	    private String city;
	    private String state;

	    
	    private String pincode;
	    @NotBlank
	    @Email(message = "invalid email address")
	    private String email;

	    @NotBlank
	    @Pattern(regexp = "^\\d{10}$",message = "invalid mobile number")
	    private String alternatePhoneNumber;

		public String getFirstName() {
			return firstName;
		}

		public void setFirstName(String firstName) {
			this.firstName = firstName;
		}

		public String getLastName() {
			return lastName;
		}

		public void setLastName(String lastName) {
			this.lastName = lastName;
		}

		public String getDateOfBirth() {
			return dateOfBirth;
		}

		public void setDateOfBirth(String dateOfBirth) {
			this.dateOfBirth = dateOfBirth;
		}

		public String getAddress() {
			return address;
		}

		public void setAddress(String address) {
			this.address = address;
		}

		public String getCity() {
			return city;
		}

		public void setCity(String city) {
			this.city = city;
		}

		public String getState() {
			return state;
		}

		public void setState(String state) {
			this.state = state;
		}

		public String getPincode() {
			return pincode;
		}

		public void setPincode(String pincode) {
			this.pincode = pincode;
		}

		public String getEmail() {
			return email;
		}

		public void setEmail(String email) {
			this.email = email;
		}

		public String getAlternatePhoneNumber() {
			return alternatePhoneNumber;
		}

		public void setAlternatePhoneNumber(String alternatePhoneNumber) {
			this.alternatePhoneNumber = alternatePhoneNumber;
		}
	    
	    
	    
}
