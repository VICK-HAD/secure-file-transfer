package com.javaexpert.secure_file_transfer.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/files")
public class FileUploadController{

    @PostMapping
    public String hello(){
        return "Hello World !";
    }
    
}