package com.talentstream.entity;
import javax.persistence.Embeddable;

@Embeddable
public class ExperienceDetails {
	 private String company;
	    private String position;
	    private String startDate;
	    private String endDate;
		public String getCompany() {
			return company;
		}
		public void setCompany(String company) {
			this.company = company;
		}
		public String getPosition() {
			return position;
		}
		public void setPosition(String position) {
			this.position = position;
		}
		public String getStartDate() {
			return startDate;
		}
		public void setStartDate(String startDate) {
			this.startDate = startDate;
		}
		public String getEndDate() {
			return endDate;
		}
		public void setEndDate(String endDate) {
			this.endDate = endDate;
		}
	    
}
