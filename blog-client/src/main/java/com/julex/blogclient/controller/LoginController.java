package com.julex.blogclient.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping(value = "login")
public class LoginController {

    @GetMapping(value = "id/{id}")
    @ResponseBody
    public String login(@PathVariable("id") String userId){
        return userId;
    }
}
