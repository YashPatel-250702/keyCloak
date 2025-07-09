package com.talentstream.entity;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import org.springframework.web.multipart.MultipartFile;

public class CustomMultipartFile implements MultipartFile {
	 private byte[] content;

		    public CustomMultipartFile(byte[] content) {
	        this.content = content;	       
	    }

	    @Override
	    public String getName() {
	        return null;
	    }

	    @Override
	    public String getOriginalFilename() {
	        return null;
	    }

	    @Override
	    public String getContentType() {
	        return null;
	    }

	    @Override
	    public boolean isEmpty() {
	        return false;
	    }

	    @Override
	    public long getSize() {
	        return content.length;
	    }

	    @Override
	    public byte[] getBytes() {
	        return content;
	    }

	    @Override
	    public InputStream getInputStream() {
	        return new ByteArrayInputStream(content);
	    }

	    		@Override
		public void transferTo(File dest) throws IOException, IllegalStateException {
	    			new FileOutputStream(dest).write(content);
		}
}