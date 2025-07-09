package com.talentstream.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.talentstream.filter.JwtRequestFilter;

@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	// @Autowired
	private UserDetailsService myUserDetailsService;
	@Autowired
	private JwtRequestFilter jwtRequestFilter;
	// @Autowired

	// @Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(myUserDetailsService).passwordEncoder(passwordEncoder());
	}

	// @Bean

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf().disable()
				.authorizeRequests()
				.antMatchers("/job/recruiters/cloneJob/{jobId}/{jobRecruiterId}", "/viewjob/recruiter/viewjob/{jobId}",
						"/applicant-image/getphoto1/{applicantId}",
						"/applyjob/recruiter/{jobRecruiterId}/appliedapplicants/{id}",
						"/recuriters/job-alerts/{recruiterId}",
						"/recuriters/appledjobs/{recruiterId}/unread-alert-count",
						"/applicantprofile/{applicantId}/profile-view1",
						"/companyprofile/approval-status/{jobRecruiterId}", "/applyjob/applied-applicant/search",
						"/applyjob/recruiter/{jobRecruiterId}/{status}", "/applyjob/appliedapplicants/{jobId}",
						"/job/recruiters/search", "/job/recruiterssearchBySkillName",
						"/applyjob/recruiter/{jobRecruiterId}/appliedapplicants",
						"/applyjob/recruiters/scheduleInterview/{applyJobId}",
						"/applyjob/recruiters/applyjob-update-status/{applyJobId}/{newStatus}",
						"/applyjob/recruiter/{recruiterId}/interviews/{status}",
						"/applyjob/recruiters/applyjobapplicantscount/{recruiterId}",
						"/applyjob/recruiters/selected/count", "/applyjob/recruiters/countShortlistedAndInterviewed",
						"/applyjob/current-date", "/companyprofile/recruiters/company-profiles/{jobRecruiterId}",
						"/companyprofile/recruiters/getCompanyProfile/{id}", "/job/recruiters/saveJob/{jobRecruiterId}",
						"/job/recruiters/viewJobs/{jobRecruiterId}", "/recuriters/viewRecruiters",
						"/job/recruiterssearchByJobTitle", "/job/recruiterssearchByLocation",
						"/job/recruiterssearchByIndustryType", "/job/recruiterssearchByEmployeeType",
						"/job/searchByMinimumQualification", "/job/recruiterssearchBySpecialization",
						"/job/recruiterssearchBySkillNameAndExperience", "/team/{recruiterId}/team-members",
						"/team/teammembers/{recruiterId}", "/team/{teamMemberId}",
						"/team/{teamMemberId}/reset-password", "/job/recruiterscountjobs/{recruiterId}")
				.hasAnyRole("JOBRECRUITER")
				.antMatchers("/jobVisit/applicant/track-visit","/skill-badges/{id}/skill-badges","/skill-badges/save","/savedjob/applicants/deletejob/{applicantId}/{jobId}", "/applicant/{id}/profilestatus",
						"/applicantprofile/{applicantId}/profile-view", "/applicantprofile/updateprofile/{applicantid}",
						"/viewjob/applicant/viewjob/{jobId}/{applicantId}",
						"/applicantprofile/createprofile/{applicantid}", "/applicantprofile/getdetails/{applicantid}",
						"/applyjob/applicants/applyjob/{applicantId}/{jobId}", "/applyjob/getAppliedJobs/{applicantId}",
						"/applyjob/getScheduleInterviews/applicant/{applicantId}/{applyJobId}",
						"/recommendedjob/findrecommendedjob/{applicantId}", "/appicant/viewApplicants",
						"/savedjob/applicants/savejob/{applicantId}/{jobId}", "/savedjob/getSavedJobs/{applicantId}",
						"/searchjob/applicant/searchjobbyskillname/{applicantId}/jobs/{skillName}",
						"/viewjob/applicant/viewjob/{jobId}", "/applicant-pdf/getresume/{applicantId}",
						"/applicant-pdf/{applicantId}/upload", "/applicant-image/{applicantId}/upload",
						"/applicant-image/getphoto/{applicantId}")
				.hasAnyRole("JOBAPPLICANT")
				.antMatchers("/resume/retryResumeRegistration","/resume/pdf/{id}", "/applicant/getApplicantById/{id}", "/send-message", "/health",
						"/applicant/signOut", "/forgotpassword/recuriterverify-otp",
						"/forgotpassword/recuritersend-otp",
						"/forgotpassword/recuriterreset-password/set-new-password/{email}",

						"/recuriters/saverecruiters", "/recuriters/recruiterLogin", "/recuriters/registration-send-otp","/api/gemini/chat",
						"/applicant/saveApplicant", "/applicant/applicantLogin", "/applicant/applicantsendotp",

						"/applicant/applicantverify-otp", "/applicant/applicantreset-password/{email}",
						"/applicant/applicantsignOut", "/applicant/forgotpasswordsendotp", "/swagger-ui/**",
						"/v3/api-docs/**", "/swagger-resources/**", "/webjars/**","/getAllJobs","/api/zoho/submit-lead","/zoho/create-lead","/zoho/update/{recordId}","/zoho/searchlead/{email}")
				.permitAll()
				// Additional antMatchers for Swagger
				.antMatchers(HttpMethod.GET, "/v2/api-docs", "/swagger-ui/**", "/swagger-resources/**", "/webjars/**")
				.permitAll()
				.anyRequest().authenticated().and()
				.exceptionHandling().and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		httpSecurity.addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);
	}
}
