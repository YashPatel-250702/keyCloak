package com.talentstream.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.talentstream.entity.ContactDetails;
 
public interface ContactDetailsRepository extends JpaRepository<ContactDetails, Long>{
 
}