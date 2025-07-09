package com.talentstream.dto;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

public class ByteArrayMultipartFile implements MultipartFile {

    private  byte[] content;
    private  String name;
    private  String originalFilename;
    private  String contentType;    

    public ByteArrayMultipartFile(byte[] imageData) {
		content=imageData;
	}

	@Override
    public String getName() {
        return name;
    }

    @Override
    public String getOriginalFilename() {
        return originalFilename;
    }

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public boolean isEmpty() {
        return content == null || content.length == 0;
    }

    @Override
    public long getSize() {
        return content.length;
    }

    @Override
    public byte[] getBytes() throws IOException {
        return content;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return isEmpty() ? null : new ByteArrayInputStream(content);
    }

   	@Override
	public void transferTo(File dest) throws IOException, IllegalStateException {
		 Files.write(dest.toPath(), content);
		
	}
}
